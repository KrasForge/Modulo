package com.modulo.cti;

import static com.modulo.cti.CtiTaxonomy.bad;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.modulo.remote.RemoteCredentialStore;
import com.modulo.remote.SafeHttpFetcher;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * TAXII 2.1 for the CTI pack.
 *
 * <p><b>Server.</b> An owner publishes TLP-capped collections. Each partner gets a token scoped to
 * one collection (read, and write when the collection accepts writes); only the SHA-256 of its
 * secret is stored and the secret is shown once. Objects are the collection's STIX export;
 * {@code date_added} is each object's {@code modified} time.
 *
 * <p><b>Client.</b> An owner subscribes to remote TAXII collections ("feeds"). A pull pages through
 * {@code objects/} from the stored {@code added_after} cursor and imports every page through the
 * idempotent STIX import. Feeds with an interval are polled by a scheduler. Feed passwords are
 * AES-GCM sealed with the server's remote-credential key and never returned.
 */
@Service
public class CtiTaxiiService {
  public static final String MEDIA_TYPE = "application/taxii+json;version=2.1";
  static final String STIX_MEDIA_TYPE = "application/stix+json;version=2.1";
  static final int MAX_PAGES = 20;
  private static final Logger logger = LoggerFactory.getLogger(CtiTaxiiService.class);

  @FunctionalInterface
  public interface Fetcher {
    SafeHttpFetcher.Response get(String url, Map<String, String> headers);
  }

  public record CollectionInput(String title, String description, String tlpCeiling, Boolean includeVictims, Boolean canRead, Boolean canWrite) {}

  public record TokenInput(String label) {}

  public record FeedInput(String title, String apiRoot, String collectionId, String username, String password,
      String defaultTlp, Integer pollMinutes, Boolean enabled) {}

  /** The owner and collection a TAXII request was authenticated for. */
  public record Principal(long owner, UUID collection, String tlpCeiling, boolean includeVictims, boolean canRead, boolean canWrite) {}

  private final JdbcTemplate jdbc;
  private final CtiExportService exports;
  private final RemoteCredentialStore credentials;
  private final Fetcher fetcher;
  private final ObjectMapper json = new ObjectMapper();
  private final SecureRandom random = new SecureRandom();

  @Autowired
  public CtiTaxiiService(JdbcTemplate jdbc, CtiExportService exports, RemoteCredentialStore credentials,
      @Value("${modulo.remote.allow-private-networks:false}") boolean allowPrivateNetworks) {
    this(jdbc, exports, credentials, SafeHttpFetcher.create(allowPrivateNetworks)::get);
  }

  CtiTaxiiService(JdbcTemplate jdbc, CtiExportService exports, RemoteCredentialStore credentials, Fetcher fetcher) {
    this.jdbc = jdbc;
    this.exports = exports;
    this.credentials = credentials;
    this.fetcher = fetcher;
  }

  // ------------------------------------------------------------------ collections and tokens

  public List<Map<String, Object>> collections(long owner) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList("SELECT * FROM cti_taxii_collections WHERE owner_id = ? ORDER BY created_at", owner)) {
      Map<String, Object> collection = collection(row);
      List<Map<String, Object>> tokens = new ArrayList<>();
      for (var token : jdbc.queryForList("SELECT id, label, created_at, last_used_at, revoked_at FROM cti_taxii_tokens"
          + " WHERE owner_id = ? AND collection_id = ? ORDER BY created_at", owner, row.get("id"))) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("id", token.get("id"));
        entry.put("label", token.get("label"));
        entry.put("createdAt", CtiService.iso(token.get("created_at")));
        entry.put("lastUsedAt", CtiService.iso(token.get("last_used_at")));
        entry.put("revokedAt", CtiService.iso(token.get("revoked_at")));
        tokens.add(entry);
      }
      collection.put("tokens", tokens);
      out.add(collection);
    }
    return out;
  }

  public Map<String, Object> createCollection(long owner, CollectionInput input) {
    if (jdbc.queryForObject("SELECT count(*) FROM cti_taxii_collections WHERE owner_id = ?", Long.class, owner) >= 50)
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "CTI_TAXII_COLLECTION_QUOTA");
    UUID id = UUID.randomUUID();
    jdbc.update("INSERT INTO cti_taxii_collections (id, owner_id, title, description, tlp_ceiling, include_victims, can_read, can_write)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)", id, owner, title(input.title()), description(input.description()),
        CtiTaxonomy.tlp(input.tlpCeiling() == null ? "green" : input.tlpCeiling()), Boolean.TRUE.equals(input.includeVictims()),
        !Boolean.FALSE.equals(input.canRead()), Boolean.TRUE.equals(input.canWrite()));
    return collections(owner).stream().filter(c -> id.equals(c.get("id"))).findFirst().orElseThrow();
  }

  public Map<String, Object> updateCollection(long owner, UUID id, CollectionInput input) {
    int updated = jdbc.update("UPDATE cti_taxii_collections SET title = ?, description = ?, tlp_ceiling = ?, include_victims = ?,"
            + " can_read = ?, can_write = ? WHERE owner_id = ? AND id = ?", title(input.title()), description(input.description()),
        CtiTaxonomy.tlp(input.tlpCeiling() == null ? "green" : input.tlpCeiling()), Boolean.TRUE.equals(input.includeVictims()),
        !Boolean.FALSE.equals(input.canRead()), Boolean.TRUE.equals(input.canWrite()), owner, id);
    if (updated == 0) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    return collections(owner).stream().filter(c -> id.equals(c.get("id"))).findFirst().orElseThrow();
  }

  public void deleteCollection(long owner, UUID id) {
    if (jdbc.update("DELETE FROM cti_taxii_collections WHERE owner_id = ? AND id = ?", owner, id) == 0)
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
  }

  /** Issues a partner token; the returned secret is never retrievable again. */
  public Map<String, Object> createToken(long owner, UUID collection, TokenInput input) {
    if (jdbc.queryForList("SELECT 1 FROM cti_taxii_collections WHERE owner_id = ? AND id = ?", owner, collection).isEmpty())
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    String label = input == null || input.label() == null || input.label().isBlank() ? "Partner" : input.label().trim();
    if (label.length() > 256) throw bad("CTI_TAXII_LABEL_TOO_LONG");
    UUID id = UUID.randomUUID();
    byte[] secret = new byte[32];
    random.nextBytes(secret);
    String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
    jdbc.update("INSERT INTO cti_taxii_tokens (id, owner_id, collection_id, label, secret_sha256) VALUES (?, ?, ?, ?, ?)",
        id, owner, collection, label, sha256(encoded));
    return Map.of("id", id, "label", label, "username", id.toString(), "password", encoded, "bearer", id + "." + encoded);
  }

  public void revokeToken(long owner, UUID token) {
    if (jdbc.update("UPDATE cti_taxii_tokens SET revoked_at = now() WHERE owner_id = ? AND id = ? AND revoked_at IS NULL", owner, token) == 0)
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
  }

  /**
   * Resolves {@code Authorization: Basic <token id:secret>} or {@code Bearer <token id>.<secret>}.
   * Returns empty for anything invalid, revoked or unknown, so callers answer a uniform 401.
   */
  public Optional<Principal> authenticate(String authorization) {
    if (authorization == null) return Optional.empty();
    String id;
    String secret;
    try {
      if (authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
        String decoded = new String(Base64.getDecoder().decode(authorization.substring(6).trim()), StandardCharsets.UTF_8);
        int colon = decoded.indexOf(':');
        if (colon < 0) return Optional.empty();
        id = decoded.substring(0, colon);
        secret = decoded.substring(colon + 1);
      } else if (authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
        String token = authorization.substring(7).trim();
        int dot = token.indexOf('.');
        if (dot < 0) return Optional.empty();
        id = token.substring(0, dot);
        secret = token.substring(dot + 1);
      } else return Optional.empty();
      UUID tokenId = UUID.fromString(id);
      var rows = jdbc.queryForList("SELECT t.owner_id, t.collection_id, t.secret_sha256, c.tlp_ceiling, c.include_victims, c.can_read,"
          + " c.can_write FROM cti_taxii_tokens t JOIN cti_taxii_collections c ON c.id = t.collection_id"
          + " WHERE t.id = ? AND t.revoked_at IS NULL", tokenId);
      if (rows.isEmpty()) return Optional.empty();
      var row = rows.get(0);
      if (!MessageDigest.isEqual((byte[]) row.get("secret_sha256"), sha256(secret))) return Optional.empty();
      jdbc.update("UPDATE cti_taxii_tokens SET last_used_at = now() WHERE id = ? AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')", tokenId);
      return Optional.of(new Principal(((Number) row.get("owner_id")).longValue(), (UUID) row.get("collection_id"),
          (String) row.get("tlp_ceiling"), (Boolean) row.get("include_victims"), (Boolean) row.get("can_read"), (Boolean) row.get("can_write")));
    } catch (IllegalArgumentException malformed) {
      return Optional.empty();
    }
  }

  public Map<String, Object> collectionResource(Principal principal) {
    var row = jdbc.queryForMap("SELECT * FROM cti_taxii_collections WHERE id = ?", principal.collection());
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", row.get("id").toString());
    out.put("title", row.get("title"));
    if (!((String) row.get("description")).isBlank()) out.put("description", row.get("description"));
    out.put("can_read", row.get("can_read"));
    out.put("can_write", row.get("can_write"));
    out.put("media_types", List.of(STIX_MEDIA_TYPE));
    return out;
  }

  /** The collection's STIX objects with their date_added, oldest first. */
  public List<Map<String, Object>> collectionObjects(Principal principal) {
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> objects = (List<Map<String, Object>>) exports.stix(principal.owner(),
        new CtiExportService.Options(principal.tlpCeiling(), principal.includeVictims(), null)).get("objects");
    List<Map<String, Object>> sorted = new ArrayList<>(objects);
    sorted.sort(Comparator.comparing((Map<String, Object> o) -> dateAdded(o)).thenComparing(o -> (String) o.get("id")));
    return sorted;
  }

  static String dateAdded(Map<String, Object> object) {
    Object modified = object.get("modified");
    if (modified == null) modified = object.get("created");
    return modified == null ? "1970-01-01T00:00:00.000Z" : modified.toString();
  }

  public Map<String, Object> importObjects(Principal principal, JsonNode envelope) {
    if (!principal.canWrite()) throw new ResponseStatusException(HttpStatus.FORBIDDEN, "CTI_TAXII_READ_ONLY");
    if (envelope == null || !envelope.path("objects").isArray()) throw bad("CTI_INVALID_TAXII_ENVELOPE");
    ObjectNode bundle = json.createObjectNode().put("type", "bundle").put("id", "bundle--" + UUID.randomUUID());
    bundle.set("objects", envelope.get("objects"));
    return exports.importStix(principal.owner(), bundle, "taxii:" + principal.collection().toString().substring(0, 8), null);
  }

  // ------------------------------------------------------------------ feeds (client)

  public List<Map<String, Object>> feeds(long owner) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList("SELECT * FROM cti_taxii_feeds WHERE owner_id = ? ORDER BY created_at", owner)) out.add(feed(row));
    return out;
  }

  public Map<String, Object> createFeed(long owner, FeedInput input) {
    if (jdbc.queryForObject("SELECT count(*) FROM cti_taxii_feeds WHERE owner_id = ?", Long.class, owner) >= 50)
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "CTI_TAXII_FEED_QUOTA");
    UUID id = UUID.randomUUID();
    String apiRoot = apiRoot(input.apiRoot());
    String collection = collectionId(input.collectionId());
    String username = input.username() == null || input.username().isBlank() ? null : input.username().trim();
    byte[] secret = input.password() == null || input.password().isBlank() ? null : credentials.seal(owner, "taxii-feed:" + id, input.password());
    jdbc.update("INSERT INTO cti_taxii_feeds (owner_id, id, title, api_root, collection_id, username, secret, default_tlp, poll_minutes, enabled)"
            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", owner, id, title(input.title()), apiRoot, collection, username, secret,
        CtiTaxonomy.tlp(input.defaultTlp() == null ? "amber" : input.defaultTlp()), pollMinutes(input.pollMinutes()), !Boolean.FALSE.equals(input.enabled()));
    return feed(jdbc.queryForMap("SELECT * FROM cti_taxii_feeds WHERE owner_id = ? AND id = ?", owner, id));
  }

  /** Updates a feed. A blank password keeps the stored one; changing the URL or collection resets the cursor. */
  public Map<String, Object> updateFeed(long owner, UUID id, FeedInput input) {
    var rows = jdbc.queryForList("SELECT * FROM cti_taxii_feeds WHERE owner_id = ? AND id = ?", owner, id);
    if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    var current = rows.get(0);
    String apiRoot = apiRoot(input.apiRoot());
    String collection = collectionId(input.collectionId());
    boolean moved = !apiRoot.equals(current.get("api_root")) || !collection.equals(current.get("collection_id"));
    byte[] secret = input.password() == null || input.password().isBlank() ? (byte[]) current.get("secret")
        : credentials.seal(owner, "taxii-feed:" + id, input.password());
    jdbc.update("UPDATE cti_taxii_feeds SET title = ?, api_root = ?, collection_id = ?, username = ?, secret = ?, default_tlp = ?,"
            + " poll_minutes = ?, enabled = ?, added_after = CASE WHEN ? THEN NULL ELSE added_after END WHERE owner_id = ? AND id = ?",
        title(input.title()), apiRoot, collection, input.username() == null || input.username().isBlank() ? null : input.username().trim(),
        secret, CtiTaxonomy.tlp(input.defaultTlp() == null ? "amber" : input.defaultTlp()), pollMinutes(input.pollMinutes()),
        !Boolean.FALSE.equals(input.enabled()), moved, owner, id);
    return feed(jdbc.queryForMap("SELECT * FROM cti_taxii_feeds WHERE owner_id = ? AND id = ?", owner, id));
  }

  public void deleteFeed(long owner, UUID id) {
    if (jdbc.update("DELETE FROM cti_taxii_feeds WHERE owner_id = ? AND id = ?", owner, id) == 0)
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
  }

  /** Pulls everything added since the feed's cursor; returns the import totals. */
  public Map<String, Object> pull(long owner, UUID id) {
    var rows = jdbc.queryForList("SELECT * FROM cti_taxii_feeds WHERE owner_id = ? AND id = ?", owner, id);
    if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    var feed = rows.get(0);
    Map<String, String> headers = new HashMap<>(Map.of("Accept", MEDIA_TYPE));
    if (feed.get("username") != null) {
      String password = credentials.open(owner, "taxii-feed:" + id, (byte[]) feed.get("secret")).orElse("");
      headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(
          (feed.get("username") + ":" + password).getBytes(StandardCharsets.UTF_8)));
    }
    String base = feed.get("api_root") + "collections/" + URLEncoder.encode((String) feed.get("collection_id"), StandardCharsets.UTF_8) + "/objects/";
    // The filter stays fixed while paging with next (TAXII 2.1 3.4); the cursor advances afterwards.
    String filterAfter = (String) feed.get("added_after");
    String addedAfter = filterAfter;
    String next = null;
    int pages = 0;
    int objects = 0;
    Map<String, Integer> totals = new TreeMap<>();
    String result;
    try {
      while (pages < MAX_PAGES) {
        StringBuilder url = new StringBuilder(base).append("?limit=500");
        if (filterAfter != null) url.append("&added_after=").append(URLEncoder.encode(filterAfter, StandardCharsets.UTF_8));
        if (next != null) url.append("&next=").append(URLEncoder.encode(next, StandardCharsets.UTF_8));
        SafeHttpFetcher.Response response = fetcher.get(url.toString(), headers);
        if (response.status() == 401 || response.status() == 403) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CTI_TAXII_UNAUTHORIZED");
        if (response.status() == 404) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CTI_TAXII_COLLECTION_NOT_FOUND");
        if (response.status() >= 400) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CTI_TAXII_ERROR_" + response.status());
        JsonNode envelope;
        try {
          envelope = json.readTree(response.body());
        } catch (java.io.IOException invalid) {
          throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CTI_TAXII_INVALID_RESPONSE");
        }
        pages++;
        JsonNode page = envelope == null ? null : envelope.path("objects");
        if (page != null && page.isArray() && page.size() > 0) {
          ObjectNode bundle = json.createObjectNode().put("type", "bundle").put("id", "bundle--" + UUID.randomUUID());
          bundle.set("objects", page);
          Map<String, Object> imported = exports.importStix(owner, bundle, "taxii:" + id.toString().substring(0, 8), (String) feed.get("default_tlp"));
          for (String key : List.of("created", "updated", "unchanged", "relationshipsCreated", "sightingsRecorded", "notesCreated"))
            if (imported.get(key) instanceof Number n) totals.merge(key, n.intValue(), Integer::sum);
          objects += page.size();
        }
        String last = response.header("X-TAXII-Date-Added-Last");
        if (last != null && (addedAfter == null || last.compareTo(addedAfter) > 0)) addedAfter = last;
        boolean more = envelope != null && envelope.path("more").asBoolean(false);
        String following = envelope == null ? null : envelope.path("next").asText(null);
        if (!more || following == null || following.equals(next)) break;
        next = following;
      }
      result = "Pulled " + objects + " objects in " + pages + (pages == 1 ? " page" : " pages") + ": "
          + totals.getOrDefault("created", 0) + " created, " + totals.getOrDefault("updated", 0) + " updated, "
          + totals.getOrDefault("unchanged", 0) + " unchanged";
    } catch (ResponseStatusException failure) {
      result = "Failed: " + failure.getReason();
      jdbc.update("UPDATE cti_taxii_feeds SET last_polled_at = now(), last_result = ? WHERE owner_id = ? AND id = ?", result, owner, id);
      throw failure;
    }
    jdbc.update("UPDATE cti_taxii_feeds SET last_polled_at = now(), last_result = ?, added_after = ? WHERE owner_id = ? AND id = ?",
        result, addedAfter, owner, id);
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("objects", objects);
    out.put("pages", pages);
    out.put("addedAfter", addedAfter);
    out.putAll(totals);
    out.put("result", result);
    return out;
  }

  /** Polls every enabled feed whose interval has elapsed. Claims each feed first, so instances never double-poll. */
  @Scheduled(fixedDelayString = "${modulo.cti.taxii.poll-check-ms:300000}", initialDelayString = "${modulo.cti.taxii.poll-initial-ms:120000}")
  public void pollDue() {
    List<Map<String, Object>> due;
    try {
      due = jdbc.queryForList("UPDATE cti_taxii_feeds SET last_polled_at = now() WHERE (owner_id, id) IN ("
          + " SELECT owner_id, id FROM cti_taxii_feeds WHERE enabled AND poll_minutes IS NOT NULL"
          + " AND (last_polled_at IS NULL OR last_polled_at < now() - make_interval(mins => poll_minutes))"
          + " ORDER BY last_polled_at NULLS FIRST LIMIT 20 FOR UPDATE SKIP LOCKED) RETURNING owner_id, id");
    } catch (RuntimeException unavailable) {
      logger.debug("TAXII poll skipped: {}", unavailable.getMessage());
      return;
    }
    for (var feed : due) {
      try {
        pull(((Number) feed.get("owner_id")).longValue(), (UUID) feed.get("id"));
      } catch (RuntimeException failure) {
        logger.info("TAXII feed {} poll failed: {}", feed.get("id"), failure.getMessage());
      }
    }
  }

  // ------------------------------------------------------------------ helpers

  private Map<String, Object> collection(Map<String, Object> row) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", row.get("id"));
    out.put("title", row.get("title"));
    out.put("description", row.get("description"));
    out.put("tlpCeiling", row.get("tlp_ceiling"));
    out.put("includeVictims", row.get("include_victims"));
    out.put("canRead", row.get("can_read"));
    out.put("canWrite", row.get("can_write"));
    out.put("createdAt", CtiService.iso(row.get("created_at")));
    return out;
  }

  private Map<String, Object> feed(Map<String, Object> row) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", row.get("id"));
    out.put("title", row.get("title"));
    out.put("apiRoot", row.get("api_root"));
    out.put("collectionId", row.get("collection_id"));
    out.put("username", row.get("username"));
    out.put("hasPassword", row.get("secret") != null);
    out.put("defaultTlp", row.get("default_tlp"));
    out.put("pollMinutes", row.get("poll_minutes"));
    out.put("enabled", row.get("enabled"));
    out.put("addedAfter", row.get("added_after"));
    out.put("lastPolledAt", CtiService.iso(row.get("last_polled_at")));
    out.put("lastResult", row.get("last_result"));
    return out;
  }

  private static String title(String value) {
    String out = value == null ? "" : value.trim();
    if (out.isEmpty()) throw bad("CTI_TAXII_TITLE_REQUIRED");
    if (out.length() > 256) throw bad("CTI_TAXII_TITLE_TOO_LONG");
    return out;
  }

  private static String description(String value) {
    String out = value == null ? "" : value.trim();
    if (out.length() > 4000) throw bad("CTI_DESCRIPTION_TOO_LONG");
    return out;
  }

  static String apiRoot(String value) {
    if (value == null || value.isBlank()) throw bad("CTI_TAXII_API_ROOT_REQUIRED");
    String root = value.trim();
    if (!root.endsWith("/")) root += "/";
    URI uri;
    try {
      uri = URI.create(root);
    } catch (IllegalArgumentException invalid) {
      throw bad("CTI_TAXII_API_ROOT_INVALID");
    }
    if (!"https".equalsIgnoreCase(uri.getScheme()) && !"http".equalsIgnoreCase(uri.getScheme())) throw bad("CTI_TAXII_API_ROOT_INVALID");
    if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null || root.length() > 2048)
      throw bad("CTI_TAXII_API_ROOT_INVALID");
    return root;
  }

  private static String collectionId(String value) {
    String out = value == null ? "" : value.trim();
    if (out.isEmpty() || out.length() > 256 || out.contains("/")) throw bad("CTI_TAXII_COLLECTION_INVALID");
    return out;
  }

  private static Integer pollMinutes(Integer value) {
    if (value == null || value == 0) return null;
    if (value < 15 || value > 10080) throw bad("CTI_TAXII_POLL_INTERVAL_INVALID");
    return value;
  }

  static byte[] sha256(String value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (java.security.NoSuchAlgorithmException failure) {
      throw new IllegalStateException(failure);
    }
  }

  static Timestamp ts(Instant instant) {
    return Timestamp.from(instant);
  }
}
