package com.modulo.cti;

import static com.modulo.cti.CtiTaxonomy.bad;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Owner-scoped threat-intelligence knowledge base: STIX-aligned objects, typed relationships,
 * an idempotent ingest path for watches and agents, and the change journal behind briefings.
 */
@Service
public class CtiService {
  static final int MAX_BATCH_OBJECTS = 1000;
  static final int MAX_BATCH_RELATIONSHIPS = 2000;
  static final int MAX_OBJECTS_PER_OWNER = 200_000;
  static final String COLUMNS = columns("");

  static String columns(String alias) {
    String a = alias.isEmpty() ? "" : alias + ".";
    return a + "id, " + a + "kind, " + a + "name, " + a + "natural_key, " + a + "status, " + a + "tlp, " + a
        + "confidence, " + a + "description, " + a + "attributes::text AS attributes, " + a + "labels::text AS labels, "
        + a + "first_seen, " + a + "last_seen, " + a + "source, " + a + "revision, " + a + "created_at, " + a + "updated_at";
  }
  /** Indicator half-life in days by indicator type; scores halve every half-life without activity. */
  static final String HALF_LIFE =
      "(CASE o.attributes->>'indicatorType' WHEN 'ipv4' THEN 30 WHEN 'ipv6' THEN 30 WHEN 'url' THEN 45"
          + " WHEN 'domain' THEN 90 WHEN 'filename' THEN 90 WHEN 'email' THEN 120 WHEN 'wallet' THEN 180"
          + " WHEN 'sha256' THEN 365 WHEN 'sha1' THEN 365 WHEN 'md5' THEN 365 WHEN 'yara' THEN 365"
          + " WHEN 'sigma' THEN 365 WHEN 'stix-pattern' THEN 365 ELSE 90 END)";
  /**
   * Indicator score (0-100): confidence (50 when unset) plus 5 per sighting in the last 30 days
   * (at most +20), halved every half-life since the last activity (latest sighting, last seen or
   * valid-from). Revoked, expired or past-valid-until indicators score 0. NULL for other kinds.
   */
  static final String SCORE =
      "(CASE WHEN o.kind <> 'indicator' THEN NULL"
          + " WHEN o.status <> 'active' OR (o.attributes->>'validUntil' IS NOT NULL AND (o.attributes->>'validUntil')::date < current_date) THEN 0"
          + " ELSE round(least(100, coalesce(o.confidence, 50) + least(20, 5 * sg.recent)) * power(0.5,"
          + " greatest(0, extract(epoch FROM now() - greatest(sg.last_sighted, o.last_seen,"
          + " coalesce((o.attributes->>'validFrom')::timestamptz, o.created_at)))) / 86400.0 / " + HALF_LIFE + "))::int END)";
  /** Objects joined with their sighting aggregates; every list/detail query reads from this. */
  static final String SCORED_FROM =
      " cti_objects o LEFT JOIN LATERAL (SELECT max(s.last_seen) AS last_sighted, count(*) AS sightings,"
          + " coalesce(sum(s.count) FILTER (WHERE s.last_seen > now() - interval '30 days'), 0) AS recent"
          + " FROM cti_sightings s WHERE s.owner_id = o.owner_id AND s.object_id = o.id) sg ON TRUE";
  static final String SCORED_COLUMNS =
      columns("o") + ", " + SCORE + " AS score, sg.last_sighted, sg.sightings, CASE WHEN o.kind = 'indicator' THEN "
          + HALF_LIFE + " END AS half_life";
  static final Set<String> SIGHTABLE = Set.of("indicator", "infrastructure", "malware", "identity", "campaign", "actor");
  static final List<String> OPINIONS = List.of("strongly-disagree", "disagree", "neutral", "agree", "strongly-agree");

  static final Map<String, String> VIEWS =
      Map.ofEntries(Map.entry("decayed-indicators",
          "o.kind = 'indicator' AND o.status = 'active' AND " + SCORE + " < 20"),
          Map.entry(
"live-c2",
          "o.kind = 'infrastructure' AND o.status = 'live' AND o.attributes->>'infraKind' IN ('c2','blob-host','dead-drop')"),
          Map.entry("unattributed-identities",
          "o.kind = 'identity' AND NOT EXISTS (WITH RECURSIVE alias_walk(id, depth) AS ("
              + " SELECT o.id, 0 UNION SELECT CASE WHEN ar.source_id = aw.id THEN ar.target_id ELSE ar.source_id END,"
              + " aw.depth + 1 FROM alias_walk aw JOIN cti_relationships ar ON ar.owner_id = o.owner_id"
              + " AND ar.type = 'alias-of' AND (ar.source_id = aw.id OR ar.target_id = aw.id) WHERE aw.depth < 6)"
              + " SELECT 1 FROM alias_walk aw JOIN cti_relationships ax ON ax.owner_id = o.owner_id"
              + " AND ((ax.source_id = aw.id AND ax.type IN ('attributed-to','part-of'))"
              + " OR (ax.target_id = aw.id AND ax.type IN ('controls','uses'))))"),
          Map.entry("open-leads",
          "o.kind = 'lead' AND o.status <> 'closed'"),
          Map.entry("stale-leads",
          "o.kind = 'lead' AND o.status <> 'closed' AND o.updated_at < now() - interval '14 days'"),
          Map.entry("expiring-indicators",
          "o.kind = 'indicator' AND o.status = 'active' AND o.attributes->>'validUntil' IS NOT NULL"
              + " AND (o.attributes->>'validUntil')::date <= current_date + 14"),
          Map.entry("unhealthy-watches",
          "o.kind = 'watch' AND (o.status = 'failing' OR (o.status = 'active' AND (o.attributes->>'lastRunAt' IS NULL"
              + " OR (o.attributes->>'lastRunAt')::timestamptz < now() - interval '2 days')))"),
          Map.entry("unnotified-victims",
          "o.kind = 'victim' AND coalesce(o.attributes->>'notified', 'false') <> 'true'"));

  private final JdbcTemplate jdbc;
  private final ObjectMapper json;
  private final CtiTaxonomy taxonomy;
  private final CtiGraphProjection graph;
  private final TransactionTemplate tx;

  public CtiService(
      JdbcTemplate jdbc,
      ObjectMapper json,
      CtiTaxonomy taxonomy,
      CtiGraphProjection graph,
      PlatformTransactionManager manager) {
    this.jdbc = jdbc;
    this.json = json;
    this.taxonomy = taxonomy;
    this.graph = graph;
    this.tx = new TransactionTemplate(manager);
  }

  public record ObjectInput(
      String kind,
      String name,
      String status,
      String tlp,
      Integer confidence,
      String description,
      JsonNode attributes,
      List<String> labels,
      String firstSeen,
      String lastSeen,
      Long revision) {}

  public record RelationshipInput(
      UUID sourceId,
      UUID targetId,
      String type,
      Integer confidence,
      String description,
      String tlp,
      String firstSeen,
      String lastSeen) {}

  public record IngestRelationship(
      JsonNode source,
      JsonNode target,
      String type,
      Integer confidence,
      String description,
      String tlp,
      String firstSeen,
      String lastSeen) {}

  public record IngestObject(
      String ref,
      String kind,
      String name,
      String status,
      String tlp,
      Integer confidence,
      String description,
      JsonNode attributes,
      List<String> labels,
      String firstSeen,
      String lastSeen) {}

  public record WatchRun(String watchType, String target, String result, String status) {}

  public record IngestSighting(
      JsonNode target,
      String firstSeen,
      String lastSeen,
      Integer count,
      String where,
      Integer confidence,
      String description,
      List<String> observed) {}

  public record IngestBatch(
      String source,
      List<IngestObject> objects,
      List<IngestRelationship> relationships,
      WatchRun watch,
      List<IngestSighting> sightings) {
    public IngestBatch(String source, List<IngestObject> objects, List<IngestRelationship> relationships, WatchRun watch) {
      this(source, objects, relationships, watch, null);
    }
  }

  public record NoteInput(String kind, String body, String opinion, String tlp, Long revision) {}

  public record SightingInput(
      String firstSeen, String lastSeen, Integer count, String where, Integer confidence, String description, List<String> observed) {}

  public record Merge(UUID into) {}

  /** A validated object write, with flags for the fields the caller actually supplied. */
  public record Candidate(
      CtiTaxonomy.Kind kind,
      String name,
      boolean nameGiven,
      String naturalKey,
      String status,
      boolean statusGiven,
      String tlp,
      boolean tlpGiven,
      Integer confidence,
      String description,
      ObjectNode attributes,
      List<String> labels,
      Instant firstSeen,
      Instant lastSeen) {}

  // ------------------------------------------------------------------ object writes

  public Map<String, Object> create(long owner, ObjectInput input, String source) {
    List<Runnable> after = new ArrayList<>();
    UUID id =
        tx.execute(
            status -> {
              quota(owner);
              Candidate c = prepare(input.kind(), input.name(), input.status(), input.tlp(), input.confidence(),
                  input.description(), input.attributes(), input.labels(), input.firstSeen(), input.lastSeen(), null);
              if (findByKey(owner, c.kind().id(), c.naturalKey(), false) != null)
                throw new ResponseStatusException(HttpStatus.CONFLICT, "CTI_DUPLICATE_OBJECT");
              UUID created = insert(owner, c, source(source));
              change(owner, created, c.kind().id(), c.name(), "created", Map.of(), source(source));
              after.add(project(owner, created, c));
              return created;
            });
    after.forEach(Runnable::run);
    return object(owner, id);
  }

  public Map<String, Object> update(long owner, UUID id, ObjectInput input, String source) {
    if (input.revision() == null) throw bad("CTI_REVISION_REQUIRED");
    List<Runnable> after = new ArrayList<>();
    tx.executeWithoutResult(
        status -> {
          Map<String, Object> existing = lock(owner, id);
          String kind = (String) existing.get("kind");
          if (input.kind() != null && !input.kind().equals(kind)) throw bad("CTI_KIND_IMMUTABLE");
          if (((Number) existing.get("revision")).longValue() != input.revision())
            throw new ResponseStatusException(HttpStatus.CONFLICT, "CTI_STALE_REVISION");
          Candidate c = prepare(kind, input.name(), input.status(), input.tlp(), input.confidence(), input.description(),
              input.attributes(), input.labels(), input.firstSeen(), input.lastSeen(), (JsonNode) existing.get("attributes"));
          Map<String, Object> other = findByKey(owner, kind, c.naturalKey(), false);
          if (other != null && !id.equals(other.get("id")))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "CTI_DUPLICATE_OBJECT");
          Map<String, Object> changed = diff(existing, c);
          write(owner, id, c);
          change(owner, id, kind, c.name(), "updated", changed, source(source));
          after.add(project(owner, id, c));
        });
    after.forEach(Runnable::run);
    return object(owner, id);
  }

  public void delete(long owner, UUID id, long revision) {
    List<Runnable> after = new ArrayList<>();
    tx.executeWithoutResult(
        status -> {
          Map<String, Object> existing = lock(owner, id);
          if (((Number) existing.get("revision")).longValue() != revision)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "CTI_STALE_REVISION");
          jdbc.update("DELETE FROM cti_objects WHERE owner_id = ? AND id = ?", owner, id);
          change(owner, id, (String) existing.get("kind"), (String) existing.get("name"), "deleted", Map.of(), "manual");
          infer(owner, "inference", after);
        });
    graph.deleteObject(owner, id);
    after.forEach(Runnable::run);
  }

  /**
   * Folds a duplicate into another object of the same kind: relationships are re-pointed (dropping
   * self-loops and duplicates), list attributes are unioned and the duplicate's name becomes an alias.
   */
  public Map<String, Object> merge(long owner, UUID sourceId, UUID targetId) {
    if (targetId == null || sourceId.equals(targetId)) throw bad("CTI_INVALID_MERGE");
    tx.executeWithoutResult(
        status -> {
          Map<String, Object> from = lock(owner, sourceId);
          Map<String, Object> into = lock(owner, targetId);
          if (!from.get("kind").equals(into.get("kind"))) throw bad("CTI_MERGE_KIND_MISMATCH");
          CtiTaxonomy.Kind kind = taxonomy.kind((String) into.get("kind"));
          // Lists are unioned; the surviving object's scalars overwrite the duplicate's.
          ObjectNode attributes = CtiValues.merge(kind, (ObjectNode) from.get("attributes"), (ObjectNode) into.get("attributes"));
          if (kind.attributes().containsKey("aliases")) {
            ArrayNode aliases = attributes.withArray("aliases");
            Set<String> seen = new HashSet<>();
            aliases.forEach(alias -> seen.add(alias.asText().toLowerCase(Locale.ROOT)));
            String name = (String) from.get("name");
            if (!name.equalsIgnoreCase((String) into.get("name")) && seen.add(name.toLowerCase(Locale.ROOT))) aliases.add(name);
          }
          List<String> labels = new ArrayList<>(strings((JsonNode) into.get("labels")));
          for (String label : strings((JsonNode) from.get("labels"))) if (!labels.contains(label)) labels.add(label);
          Integer confidence = max((Integer) from.get("confidence"), (Integer) into.get("confidence"));
          jdbc.update(
              "UPDATE cti_objects SET attributes = CAST(? AS jsonb), labels = CAST(? AS jsonb), confidence = ?,"
                  + " tlp = ?, first_seen = (SELECT min(v) FROM unnest(ARRAY[first_seen, ?::timestamptz]) v),"
                  + " last_seen = (SELECT max(v) FROM unnest(ARRAY[last_seen, ?::timestamptz]) v),"
                  + " revision = revision + 1, updated_at = now() WHERE owner_id = ? AND id = ?",
              text(attributes), text(labels), confidence,
              CtiTaxonomy.stricterTlp((String) from.get("tlp"), (String) into.get("tlp")),
              timestamp((String) from.get("firstSeen")), timestamp((String) from.get("lastSeen")), owner, targetId);
          // Re-point edges; ON CONFLICT drops duplicates, the self-loop filter drops into<->from edges.
          jdbc.update(
              "INSERT INTO cti_relationships (owner_id, id, source_id, target_id, type, confidence, description, tlp,"
                  + " first_seen, last_seen, source, created_at, updated_at)"
                  + " SELECT owner_id, gen_random_uuid(), CASE WHEN source_id = ? THEN ? ELSE source_id END,"
                  + " CASE WHEN target_id = ? THEN ? ELSE target_id END, type, confidence, description, tlp, first_seen,"
                  + " last_seen, source, created_at, now() FROM cti_relationships"
                  + " WHERE owner_id = ? AND inferred_by IS NULL AND (source_id = ? OR target_id = ?)"
                  + " AND NOT ((source_id = ? AND target_id = ?) OR (source_id = ? AND target_id = ?))"
                  + " ON CONFLICT (owner_id, source_id, target_id, type) DO NOTHING",
              sourceId, targetId, sourceId, targetId, owner, sourceId, sourceId, sourceId, targetId, targetId, sourceId);
          jdbc.update("DELETE FROM cti_objects WHERE owner_id = ? AND id = ?", owner, sourceId);
          change(owner, targetId, kind.id(), (String) into.get("name"), "merged",
              Map.of("mergedId", sourceId.toString(), "mergedName", from.get("name")), "manual");
          change(owner, sourceId, kind.id(), (String) from.get("name"), "deleted",
              Map.of("mergedInto", targetId.toString()), "manual");
          infer(owner, "inference", new ArrayList<>());
        });
    reproject(owner);
    return object(owner, targetId);
  }

  // ------------------------------------------------------------------ relationships

  public Map<String, Object> link(long owner, RelationshipInput input, String source) {
    List<Runnable> after = new ArrayList<>();
    Map<String, Object> result =
        tx.execute(status -> {
          var linked = upsertRelationship(owner, input, source(source), after);
          infer(owner, "inference", after);
          return linked;
        });
    after.forEach(Runnable::run);
    return result;
  }

  public void unlink(long owner, UUID id) {
    List<Runnable> after = new ArrayList<>();
    tx.executeWithoutResult(
        status -> {
          var inferred = jdbc.queryForList("SELECT inferred_by FROM cti_relationships WHERE owner_id = ? AND id = ?", String.class, owner, id);
          if (!inferred.isEmpty() && inferred.get(0) != null)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "CTI_INFERRED_RELATIONSHIP");
          var rows = jdbc.queryForList(
              "DELETE FROM cti_relationships r USING cti_objects o WHERE r.owner_id = ? AND r.id = ?"
                  + " AND o.owner_id = r.owner_id AND o.id = r.source_id RETURNING r.type, r.target_id, o.id AS oid, o.kind, o.name",
              owner, id);
          if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
          var row = rows.get(0);
          change(owner, (UUID) row.get("oid"), (String) row.get("kind"), (String) row.get("name"), "unlinked",
              Map.of("type", row.get("type"), "targetId", row.get("target_id").toString()), "manual");
          infer(owner, "inference", after);
        });
    graph.deleteRelationship(owner, id);
    after.forEach(Runnable::run);
  }

  private Map<String, Object> upsertRelationship(long owner, RelationshipInput input, String source, List<Runnable> after) {
    if (input.sourceId() == null || input.targetId() == null) throw bad("CTI_RELATIONSHIP_ENDPOINT_REQUIRED");
    if (input.sourceId().equals(input.targetId())) throw bad("CTI_SELF_RELATIONSHIP");
    Map<String, Object> from = head(owner, input.sourceId());
    Map<String, Object> to = head(owner, input.targetId());
    taxonomy.requireRelationship(input.type(), (String) from.get("kind"), (String) to.get("kind"));
    String tlp = input.tlp() == null || input.tlp().isBlank()
        ? CtiTaxonomy.stricterTlp((String) from.get("tlp"), (String) to.get("tlp"))
        : CtiTaxonomy.tlp(input.tlp());
    Integer confidence = confidence(input.confidence());
    String description = description(input.description());
    Instant first = CtiValues.instant(input.firstSeen());
    Instant last = CtiValues.instant(input.lastSeen());
    // An analyst or ingest asserting an inferred edge promotes it to an explicit one.
    boolean wasInferred = !jdbc.queryForList(
        "SELECT 1 FROM cti_relationships WHERE owner_id = ? AND source_id = ? AND target_id = ? AND type = ? AND inferred_by IS NOT NULL",
        owner, input.sourceId(), input.targetId(), input.type()).isEmpty();
    var row = jdbc.queryForMap(
        "INSERT INTO cti_relationships (owner_id, id, source_id, target_id, type, confidence, description, tlp,"
            + " first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            + " ON CONFLICT (owner_id, source_id, target_id, type) DO UPDATE SET"
            + " confidence = coalesce(EXCLUDED.confidence, cti_relationships.confidence),"
            + " description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE cti_relationships.description END,"
            + " first_seen = least(cti_relationships.first_seen, EXCLUDED.first_seen),"
            + " last_seen = greatest(cti_relationships.last_seen, EXCLUDED.last_seen), inferred_by = NULL, updated_at = now()"
            + " RETURNING id, (xmax = 0) AS inserted",
        owner, UUID.randomUUID(), input.sourceId(), input.targetId(), input.type(), confidence, description, tlp,
        ts(first), ts(last), source);
    UUID id = (UUID) row.get("id");
    boolean inserted = Boolean.TRUE.equals(row.get("inserted")) || wasInferred;
    if (inserted) {
      change(owner, input.sourceId(), (String) from.get("kind"), (String) from.get("name"), "linked",
          Map.of("type", input.type(), "targetId", input.targetId().toString(), "targetName", to.get("name")), source);
      after.add(() -> graph.upsertRelationship(owner, id, input.sourceId(), input.targetId(), input.type()));
    }
    return Map.of("id", id, "created", inserted);
  }

  // ------------------------------------------------------------------ ingest

  /**
   * Idempotent batch upsert keyed by (kind, natural key). Incoming scalars win, list attributes are
   * unioned, the seen window only widens and TLP is never downgraded automatically. Relationship
   * endpoints are batch refs, object ids, or {@code {"kind","key"}} natural-key lookups.
   */
  public Map<String, Object> ingest(long owner, IngestBatch batch) {
    return ingest(owner, batch, MAX_BATCH_OBJECTS);
  }

  /** Ingest with a caller-chosen object limit (CSV and TAXII imports allow larger batches). */
  Map<String, Object> ingest(long owner, IngestBatch batch, int maxObjects) {
    List<IngestObject> objects = batch.objects() == null ? List.of() : batch.objects();
    List<IngestRelationship> relationships = batch.relationships() == null ? List.of() : batch.relationships();
    List<IngestSighting> sightings = batch.sightings() == null ? List.of() : batch.sightings();
    if (objects.size() > maxObjects || relationships.size() > Math.max(MAX_BATCH_RELATIONSHIPS, maxObjects * 2)
        || sightings.size() > MAX_BATCH_RELATIONSHIPS)
      throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "CTI_BATCH_TOO_LARGE");
    if (objects.isEmpty() && relationships.isEmpty() && sightings.isEmpty() && batch.watch() == null) throw bad("CTI_EMPTY_BATCH");
    String source = source(batch.source() == null ? "ingest" : batch.source());
    List<Runnable> after = new ArrayList<>();
    Map<String, Object> result =
        tx.execute(
            status -> {
              Map<String, UUID> refs = new HashMap<>();
              List<Map<String, Object>> results = new ArrayList<>();
              int[] counts = new int[3];
              Set<UUID> touched = new LinkedHashSet<>();
              for (IngestObject item : objects) {
                if (item == null) throw bad("CTI_INVALID_OBJECT");
                Map<String, Object> outcome = upsert(owner, item, source, after);
                String action = (String) outcome.get("action");
                counts["created".equals(action) ? 0 : "updated".equals(action) ? 1 : 2]++;
                touched.add((UUID) outcome.get("id"));
                if (item.ref() != null && !item.ref().isBlank()) {
                  if (refs.put(item.ref(), (UUID) outcome.get("id")) != null) throw bad("CTI_DUPLICATE_REF");
                  outcome.put("ref", item.ref());
                }
                results.add(outcome);
              }
              int linked = 0;
              for (IngestRelationship rel : relationships) {
                if (rel == null) throw bad("CTI_INVALID_RELATIONSHIP");
                UUID from = resolve(owner, rel.source(), refs);
                UUID to = resolve(owner, rel.target(), refs);
                var outcome = upsertRelationship(owner, new RelationshipInput(from, to, rel.type(), rel.confidence(),
                    rel.description(), rel.tlp(), rel.firstSeen(), rel.lastSeen()), source, after);
                if (Boolean.TRUE.equals(outcome.get("created"))) linked++;
              }
              int sighted = 0;
              for (IngestSighting sighting : sightings) {
                if (sighting == null) throw bad("CTI_INVALID_SIGHTING");
                UUID target = resolve(owner, sighting.target(), refs);
                if (recordSighting(owner, target, new SightingInput(sighting.firstSeen(), sighting.lastSeen(), sighting.count(),
                    sighting.where(), sighting.confidence(), sighting.description(), sighting.observed()), source) != null) sighted++;
              }
              Map<String, Object> out = new LinkedHashMap<>();
              out.put("created", counts[0]);
              out.put("updated", counts[1]);
              out.put("unchanged", counts[2]);
              out.put("relationshipsCreated", linked);
              out.put("sightingsRecorded", sighted);
              out.put("results", results);
              if (batch.watch() != null) out.put("watch", recordWatch(owner, batch.watch(), counts[0], touched, source, after));
              out.put("inferred", infer(owner, "inference", after));
              return out;
            });
    after.forEach(Runnable::run);
    return result;
  }

  private Map<String, Object> upsert(long owner, IngestObject item, String source, List<Runnable> after) {
    Candidate c = prepare(item.kind(), item.name(), item.status(), item.tlp(), item.confidence(), item.description(),
        item.attributes(), item.labels(), item.firstSeen(), item.lastSeen(), null);
    Map<String, Object> existing = findByKey(owner, c.kind().id(), c.naturalKey(), true);
    if (existing == null) {
      quota(owner);
      UUID id = UUID.randomUUID();
      int inserted = jdbc.update(insertSql() + " ON CONFLICT (owner_id, kind, natural_key) DO NOTHING", insertArgs(owner, id, c, source));
      if (inserted == 1) {
        change(owner, id, c.kind().id(), c.name(), "created", Map.of(), source);
        after.add(project(owner, id, c));
        return new LinkedHashMap<>(Map.of("id", id, "kind", c.kind().id(), "action", "created"));
      }
      existing = findByKey(owner, c.kind().id(), c.naturalKey(), true);
    }
    UUID id = (UUID) existing.get("id");
    ObjectNode attributes = CtiValues.merge(c.kind(), (ObjectNode) existing.get("attributes"), c.attributes());
    List<String> labels = new ArrayList<>(strings((JsonNode) existing.get("labels")));
    for (String label : c.labels()) if (!labels.contains(label)) labels.add(label);
    Instant first = min(CtiValues.instant((String) existing.get("firstSeen")), c.firstSeen());
    Instant last = maxInstant(CtiValues.instant((String) existing.get("lastSeen")), c.lastSeen());
    Candidate merged = new Candidate(
        c.kind(), (String) existing.get("name"), false, (String) existing.get("naturalKey"),
        c.statusGiven() ? c.status() : (String) existing.get("status"), false,
        CtiTaxonomy.stricterTlp((String) existing.get("tlp"), c.tlpGiven() ? c.tlp() : null), false,
        c.confidence() != null ? c.confidence() : (Integer) existing.get("confidence"),
        c.description().isBlank() ? (String) existing.get("description") : c.description(),
        attributes, List.copyOf(labels), first, last);
    Map<String, Object> changed = diff(existing, merged);
    if (((List<?>) changed.get("fields")).isEmpty()) return new LinkedHashMap<>(Map.of("id", id, "kind", c.kind().id(), "action", "unchanged"));
    write(owner, id, merged);
    change(owner, id, c.kind().id(), merged.name(), "updated", changed, source);
    after.add(project(owner, id, merged));
    return new LinkedHashMap<>(Map.of("id", id, "kind", c.kind().id(), "action", "updated"));
  }

  private UUID recordWatch(long owner, WatchRun run, int created, Set<UUID> touched, String source, List<Runnable> after) {
    ObjectNode attributes = json.createObjectNode();
    attributes.put("watchType", run.watchType());
    attributes.put("target", run.target());
    attributes.put("lastRunAt", Instant.now().toString());
    if (run.result() != null && !run.result().isBlank()) attributes.put("lastResult", run.result());
    Candidate probe = prepare("watch", null, null, null, null, null, attributes, null, null, null, null);
    Map<String, Object> existing = findByKey(owner, "watch", probe.naturalKey(), true);
    double previous = existing == null ? 0 : ((JsonNode) existing.get("attributes")).path("findings").asDouble(0);
    attributes.put("findings", (long) previous + created);
    String status = run.status() == null || run.status().isBlank() ? "active" : run.status();
    var outcome = upsert(owner, new IngestObject(null, "watch", null, status, null, null, null, attributes, null, null, null), source, after);
    UUID watch = (UUID) outcome.get("id");
    for (UUID object : touched)
      if (!object.equals(watch))
        upsertRelationship(owner, new RelationshipInput(watch, object, "concerns", null, null, null, null, null), source, after);
    return watch;
  }

  private UUID resolve(long owner, JsonNode ref, Map<String, UUID> refs) {
    if (ref == null || ref.isNull()) throw bad("CTI_UNRESOLVED_REFERENCE");
    if (ref.isTextual()) {
      UUID batch = refs.get(ref.asText());
      if (batch != null) return batch;
      try {
        UUID id = UUID.fromString(ref.asText());
        head(owner, id);
        return id;
      } catch (IllegalArgumentException notUuid) {
        throw bad("CTI_UNRESOLVED_REFERENCE");
      }
    }
    if (ref.has("ref") && refs.containsKey(ref.path("ref").asText())) return refs.get(ref.path("ref").asText());
    if (ref.has("id")) return resolve(owner, ref.get("id"), refs);
    if (ref.has("kind") && ref.has("key")) {
      String kind = taxonomy.kind(ref.path("kind").asText()).id();
      Map<String, Object> found = findByKey(owner, kind, CtiValues.normalizeKey(ref.path("key").asText()), false);
      if (found != null) return (UUID) found.get("id");
    }
    throw bad("CTI_UNRESOLVED_REFERENCE");
  }

  // ------------------------------------------------------------------ reads

  public Map<String, Object> object(long owner, UUID id) {
    var rows = jdbc.queryForList("SELECT " + SCORED_COLUMNS + " FROM" + SCORED_FROM + " WHERE o.owner_id = ? AND o.id = ?", owner, id);
    if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    return row(rows.get(0));
  }

  /** The object plus every relationship, with the far endpoint summarized, and its history. */
  public Map<String, Object> detail(long owner, UUID id) {
    Map<String, Object> out = object(owner, id);
    List<Map<String, Object>> relationships = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT r.id, r.type, r.source_id, r.target_id, r.confidence, r.description, r.tlp, r.first_seen, r.last_seen,"
            + " r.source, r.created_at, r.inferred_by, o.id AS other_id, o.kind AS other_kind, o.name AS other_name,"
            + " o.status AS other_status, o.tlp AS other_tlp FROM cti_relationships r JOIN cti_objects o"
            + " ON o.owner_id = r.owner_id AND o.id = CASE WHEN r.source_id = ? THEN r.target_id ELSE r.source_id END"
            + " WHERE r.owner_id = ? AND (r.source_id = ? OR r.target_id = ?) ORDER BY r.type, lower(o.name) LIMIT 2000",
        id, owner, id, id)) {
      Map<String, Object> rel = new LinkedHashMap<>();
      rel.put("id", row.get("id"));
      rel.put("type", row.get("type"));
      rel.put("direction", id.equals(row.get("source_id")) ? "outgoing" : "incoming");
      rel.put("sourceId", row.get("source_id"));
      rel.put("targetId", row.get("target_id"));
      rel.put("confidence", row.get("confidence"));
      rel.put("description", row.get("description"));
      rel.put("tlp", row.get("tlp"));
      rel.put("firstSeen", iso(row.get("first_seen")));
      rel.put("lastSeen", iso(row.get("last_seen")));
      rel.put("source", row.get("source"));
      rel.put("inferredBy", row.get("inferred_by"));
      rel.put("other", Map.of("id", row.get("other_id"), "kind", row.get("other_kind"), "name", row.get("other_name"),
          "status", row.get("other_status"), "tlp", row.get("other_tlp")));
      relationships.add(rel);
    }
    out.put("relationships", relationships);
    out.put("notes", notes(owner, id));
    out.put("sightings", sightings(owner, id));
    out.put("history", changes(owner, null, id, 50).get("items"));
    return out;
  }

  public Map<String, Object> list(
      long owner, String kind, String view, String q, String status, String tlp, String label, int page, int limit) {
    if (page < 0 || limit < 1 || limit > 200) throw bad("CTI_INVALID_PAGE");
    StringBuilder where = new StringBuilder(" WHERE o.owner_id = ?");
    List<Object> args = new ArrayList<>(List.of(owner));
    if (kind != null && !kind.isBlank()) {
      where.append(" AND o.kind = ?");
      args.add(taxonomy.kind(kind).id());
    }
    if (view != null && !view.isBlank()) {
      String predicate = VIEWS.get(view);
      if (predicate == null) throw bad("CTI_UNKNOWN_VIEW");
      where.append(" AND ").append(predicate);
    }
    if (q != null && !q.isBlank()) {
      if (q.length() > 256) throw bad("CTI_QUERY_TOO_LONG");
      String pattern = "%" + CtiValues.refang(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%";
      where.append(" AND (o.name ILIKE ? OR o.natural_key ILIKE ? OR o.attributes::text ILIKE ? OR o.description ILIKE ?)");
      args.addAll(List.of(pattern, pattern, pattern, pattern));
    }
    if (status != null && !status.isBlank()) {
      where.append(" AND o.status = ?");
      args.add(status);
    }
    if (tlp != null && !tlp.isBlank()) {
      where.append(" AND o.tlp = ?");
      args.add(CtiTaxonomy.tlp(tlp));
    }
    if (label != null && !label.isBlank()) {
      where.append(" AND o.labels @> CAST(? AS jsonb)");
      args.add(text(List.of(label.toLowerCase(Locale.ROOT))));
    }
    long total = jdbc.queryForObject("SELECT count(*) FROM" + SCORED_FROM + where, Long.class, args.toArray());
    String order = view != null && view.endsWith("leads")
        ? " ORDER BY coalesce(o.attributes->>'priority', 'P9'), o.updated_at DESC, o.id"
        : "decayed-indicators".equals(view) ? " ORDER BY " + SCORE + ", o.updated_at DESC, o.id"
        : " ORDER BY o.updated_at DESC, o.id";
    List<Object> pageArgs = new ArrayList<>(args);
    pageArgs.add(limit);
    pageArgs.add((long) page * limit);
    List<Map<String, Object>> items = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT " + SCORED_COLUMNS
            + ", (SELECT count(*) FROM cti_relationships r WHERE r.owner_id = o.owner_id AND (r.source_id = o.id OR r.target_id = o.id)) AS degree"
            + " FROM" + SCORED_FROM + where + order + " LIMIT ? OFFSET ?",
        pageArgs.toArray())) {
      Map<String, Object> item = row(row);
      item.put("degree", ((Number) row.get("degree")).longValue());
      items.add(item);
    }
    return Map.of("items", items, "total", total, "page", page, "limit", limit, "hasMore", (long) (page + 1) * limit < total);
  }

  /** Neighbourhood (focus + depth) or recent-overview subgraph, read from Postgres. */
  public Map<String, Object> graph(long owner, UUID focus, int depth, int limit, boolean includeWorkflow) {
    if (depth < 1 || depth > 3 || limit < 1 || limit > 1000) throw bad("CTI_INVALID_GRAPH_REQUEST");
    // Without workflow records, leads/watches never act as bridges that connect unrelated clusters.
    String knowledge = includeWorkflow ? "TRUE" : "n.kind IN ('actor','identity','infrastructure','malware','indicator','campaign','victim')";
    List<Map<String, Object>> nodes;
    if (focus != null) {
      head(owner, focus);
      nodes = jdbc.queryForList(
          "WITH RECURSIVE walk(id, depth) AS (SELECT ?::uuid, 0 UNION"
              + " SELECT n.id, w.depth + 1 FROM walk w JOIN cti_relationships r ON r.owner_id = ?"
              + " AND (r.source_id = w.id OR r.target_id = w.id) JOIN cti_objects n ON n.owner_id = r.owner_id"
              + " AND n.id = CASE WHEN r.source_id = w.id THEN r.target_id ELSE r.source_id END"
              + " WHERE w.depth < ? AND " + knowledge + "), reached AS (SELECT id, min(depth) AS depth FROM walk GROUP BY id)"
              + " SELECT o.id, o.kind, o.name, o.status, o.tlp, o.confidence, reached.depth FROM reached JOIN cti_objects o"
              + " ON o.owner_id = ? AND o.id = reached.id ORDER BY reached.depth, o.updated_at DESC LIMIT ?",
          focus, owner, depth, owner, limit);
    } else {
      nodes = jdbc.queryForList(
          "SELECT n.id, n.kind, n.name, n.status, n.tlp, n.confidence, 0 AS depth FROM cti_objects n WHERE n.owner_id = ?"
              + " AND " + knowledge + " ORDER BY n.updated_at DESC LIMIT ?",
          owner, limit);
    }
    String ids = "{" + String.join(",", nodes.stream().map(node -> node.get("id").toString()).toList()) + "}";
    List<Map<String, Object>> edges = nodes.isEmpty() ? List.of() : jdbc.queryForList(
        "SELECT id, source_id AS \"sourceId\", target_id AS \"targetId\", type, confidence, inferred_by AS \"inferredBy\" FROM cti_relationships"
            + " WHERE owner_id = ? AND source_id = ANY(CAST(? AS uuid[])) AND target_id = ANY(CAST(? AS uuid[])) LIMIT 5000",
        owner, ids, ids);
    return Map.of("nodes", nodes, "edges", edges, "focus", focus == null ? "" : focus.toString(),
        "projection", graph.isAvailable() ? "neo4j" : "postgres-only");
  }

  public Map<String, Object> changes(long owner, String since, UUID objectId, int limit) {
    if (limit < 1 || limit > 500) throw bad("CTI_INVALID_PAGE");
    Instant from = since == null || since.isBlank() ? Instant.EPOCH : CtiValues.instant(since);
    List<Object> args = new ArrayList<>(List.of(owner, Timestamp.from(from)));
    String filter = "";
    if (objectId != null) {
      filter = " AND object_id = ?";
      args.add(objectId);
    }
    args.add(limit);
    List<Map<String, Object>> items = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT seq, object_id, kind, name, action, detail::text AS detail, source, at FROM cti_changes"
            + " WHERE owner_id = ? AND at >= ?" + filter + " ORDER BY seq DESC LIMIT ?", args.toArray())) {
      Map<String, Object> item = new LinkedHashMap<>();
      item.put("seq", row.get("seq"));
      item.put("objectId", row.get("object_id"));
      item.put("kind", row.get("kind"));
      item.put("name", row.get("name"));
      item.put("action", row.get("action"));
      item.put("detail", read((String) row.get("detail")));
      item.put("source", row.get("source"));
      item.put("at", iso(row.get("at")));
      items.add(item);
    }
    Map<String, Long> byAction = new TreeMap<>();
    for (var row : jdbc.queryForList(
        "SELECT action, count(*) AS n FROM cti_changes WHERE owner_id = ? AND at >= ?" + (objectId == null ? "" : " AND object_id = ?")
            + " GROUP BY action", objectId == null ? new Object[] {owner, Timestamp.from(from)} : new Object[] {owner, Timestamp.from(from), objectId}))
      byAction.put((String) row.get("action"), ((Number) row.get("n")).longValue());
    return Map.of("items", items, "since", from.toString(), "totals", byAction);
  }

  public Map<String, Object> summary(long owner) {
    Map<String, Long> counts = new TreeMap<>();
    for (var kind : taxonomy.kinds()) counts.put(kind.id(), 0L);
    for (var row : jdbc.queryForList("SELECT kind, count(*) AS n FROM cti_objects WHERE owner_id = ? GROUP BY kind", owner))
      counts.put((String) row.get("kind"), ((Number) row.get("n")).longValue());
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("counts", counts);
    out.put("relationships", jdbc.queryForObject("SELECT count(*) FROM cti_relationships WHERE owner_id = ?", Long.class, owner));
    Map<String, Object> views = new LinkedHashMap<>();
    for (String view : List.of("live-c2", "open-leads", "stale-leads", "unattributed-identities", "expiring-indicators",
        "decayed-indicators", "unhealthy-watches", "unnotified-victims"))
      views.put(view, list(owner, null, view, null, null, null, null, 0, 10));
    out.put("views", views);
    out.put("recentChanges", changes(owner, Instant.now().minusSeconds(7 * 86400).toString(), null, 25));
    out.put("inferredRelationships", jdbc.queryForObject(
        "SELECT count(*) FROM cti_relationships WHERE owner_id = ? AND inferred_by IS NOT NULL", Long.class, owner));
    out.put("sightingsLast30Days", jdbc.queryForObject(
        "SELECT coalesce(sum(count), 0) FROM cti_sightings WHERE owner_id = ? AND last_seen > now() - interval '30 days'", Long.class, owner));
    out.put("graphProjection", graph.isAvailable() ? "neo4j" : "postgres-only");
    return out;
  }

  public Map<String, Object> taxonomy() {
    return Map.of("kinds", taxonomy.kinds(), "relationshipTypes", taxonomy.relationshipTypes(), "tlp", CtiTaxonomy.TLP,
        "views", new TreeSet<>(VIEWS.keySet()));
  }

  /** All rows of the owner, for exports and reprojection. */
  List<Map<String, Object>> allObjects(long owner) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList("SELECT " + SCORED_COLUMNS + " FROM" + SCORED_FROM
        + " WHERE o.owner_id = ? ORDER BY o.created_at, o.id LIMIT ?", owner, MAX_OBJECTS_PER_OWNER)) out.add(row(row));
    return out;
  }

  List<Map<String, Object>> allRelationships(long owner) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT id, source_id, target_id, type, confidence, description, tlp, first_seen, last_seen, created_at, updated_at,"
            + " inferred_by FROM cti_relationships WHERE owner_id = ? ORDER BY created_at, id", owner)) {
      Map<String, Object> rel = new LinkedHashMap<>();
      rel.put("id", row.get("id"));
      rel.put("sourceId", row.get("source_id"));
      rel.put("targetId", row.get("target_id"));
      rel.put("type", row.get("type"));
      rel.put("confidence", row.get("confidence"));
      rel.put("description", row.get("description"));
      rel.put("tlp", row.get("tlp"));
      rel.put("firstSeen", iso(row.get("first_seen")));
      rel.put("lastSeen", iso(row.get("last_seen")));
      rel.put("createdAt", iso(row.get("created_at")));
      rel.put("updatedAt", iso(row.get("updated_at")));
      rel.put("inferredBy", row.get("inferred_by"));
      out.add(rel);
    }
    return out;
  }

  public Map<String, Object> reproject(long owner) {
    boolean done = graph.reproject(owner, allObjects(owner), allRelationships(owner));
    return Map.of("projected", done, "projection", graph.isAvailable() ? "neo4j" : "postgres-only");
  }

  /** Internal write used by the export service to stamp read-only capsule attributes. */
  void stamp(long owner, UUID id, Map<String, String> readOnlyAttributes, String action, Map<String, Object> detail) {
    tx.executeWithoutResult(status -> {
      Map<String, Object> existing = lock(owner, id);
      ObjectNode attributes = ((ObjectNode) existing.get("attributes")).deepCopy();
      readOnlyAttributes.forEach(attributes::put);
      jdbc.update("UPDATE cti_objects SET attributes = CAST(? AS jsonb), revision = revision + 1, updated_at = now()"
          + " WHERE owner_id = ? AND id = ?", text(attributes), owner, id);
      change(owner, id, (String) existing.get("kind"), (String) existing.get("name"), action, detail, "manual");
    });
  }

  // ------------------------------------------------------------------ inference

  /** One derived edge: what the rule concluded and the confidence it carries over. */
  record Inferred(UUID source, UUID target, String type, String rule, Integer confidence) {}

  private record Edge(UUID id, UUID source, UUID target, String type, Integer confidence, String inferredBy,
      String sourceKind, String targetKind, String sourceName, String targetName, String sourceTlp, String targetTlp) {}

  static final Set<String> ATTRIBUTION_TARGETS = Set.of("actor", "campaign");

  /**
   * Recomputes every inferred relationship of the owner and applies the difference:
   * <ul>
   *   <li>{@code alias-attribution}: identities joined by {@code alias-of} share every attribution
   *       ({@code attributed-to} an actor or campaign) of any member;</li>
   *   <li>{@code rotation-inheritance}: infrastructure joined by {@code rotation-of} shares the
   *       attributions of any member, and whoever {@code uses} one member uses them all;</li>
   *   <li>{@code indicator-propagation}: an indicator {@code based-on} an observable {@code indicates}
   *       every actor or campaign the observable is attributed to or used by (including the edges
   *       the first two rules derived).</li>
   * </ul>
   * Only explicit edges are premises of the first two rules, so retracting an explicit edge always
   * retracts what was derived from it. An explicit edge with the same endpoints and type wins.
   *
   * @return the number of edges added and retracted
   */
  Map<String, Integer> infer(long owner, String source, List<Runnable> after) {
    List<Edge> edges = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT r.id, r.source_id, r.target_id, r.type, r.confidence, r.inferred_by, s.kind AS sk, t.kind AS tk,"
            + " s.name AS sn, t.name AS tn, s.tlp AS stlp, t.tlp AS ttlp FROM cti_relationships r"
            + " JOIN cti_objects s ON s.owner_id = r.owner_id AND s.id = r.source_id"
            + " JOIN cti_objects t ON t.owner_id = r.owner_id AND t.id = r.target_id"
            + " WHERE r.owner_id = ? AND r.type IN ('alias-of','attributed-to','rotation-of','uses','based-on','indicates')",
        owner))
      edges.add(new Edge((UUID) row.get("id"), (UUID) row.get("source_id"), (UUID) row.get("target_id"), (String) row.get("type"),
          row.get("confidence") == null ? null : ((Number) row.get("confidence")).intValue(), (String) row.get("inferred_by"),
          (String) row.get("sk"), (String) row.get("tk"), (String) row.get("sn"), (String) row.get("tn"),
          (String) row.get("stlp"), (String) row.get("ttlp")));
    Map<UUID, String[]> heads = new HashMap<>();
    for (Edge e : edges) {
      heads.put(e.source(), new String[] {e.sourceKind(), e.sourceName(), e.sourceTlp()});
      heads.put(e.target(), new String[] {e.targetKind(), e.targetName(), e.targetTlp()});
    }
    List<Edge> explicit = edges.stream().filter(e -> e.inferredBy() == null).toList();
    Set<List<Object>> asserted = new HashSet<>();
    for (Edge e : explicit) asserted.add(List.of(e.source(), e.target(), e.type()));
    Map<List<Object>, Inferred> desired = new LinkedHashMap<>();
    java.util.function.Consumer<Inferred> want = edge -> {
      List<Object> key = List.of(edge.source(), edge.target(), edge.type());
      if (!edge.source().equals(edge.target()) && !asserted.contains(key)) desired.putIfAbsent(key, edge);
    };

    // Rule 1 and 2: components joined by alias-of (identities) or rotation-of (infrastructure).
    for (String[] rule : new String[][] {{"alias-of", "identity", "alias-attribution"}, {"rotation-of", "infrastructure", "rotation-inheritance"}}) {
      Map<UUID, UUID> parent = new HashMap<>();
      for (Edge e : explicit)
        if (e.type().equals(rule[0]) && e.sourceKind().equals(rule[1]) && e.targetKind().equals(rule[1])) union(parent, e.source(), e.target());
      Map<UUID, List<UUID>> components = new HashMap<>();
      for (UUID member : new ArrayList<>(parent.keySet())) components.computeIfAbsent(find(parent, member), k -> new ArrayList<>()).add(member);
      for (List<UUID> members : components.values()) {
        Set<UUID> set = new HashSet<>(members);
        for (Edge e : explicit) {
          if (e.type().equals("attributed-to") && set.contains(e.source()) && ATTRIBUTION_TARGETS.contains(e.targetKind()))
            for (UUID member : members) want.accept(new Inferred(member, e.target(), "attributed-to", rule[2], e.confidence()));
          if (rule[1].equals("infrastructure") && e.type().equals("uses") && set.contains(e.target()))
            for (UUID member : members) want.accept(new Inferred(e.source(), member, "uses", rule[2], e.confidence()));
        }
      }
    }
    // Rule 3: indicator based-on X, X attributed to / used by an actor or campaign.
    Map<UUID, Map<UUID, Integer>> attributedTo = new HashMap<>();
    List<Inferred> premises = new ArrayList<>(desired.values());
    for (Edge e : explicit) premises.add(new Inferred(e.source(), e.target(), e.type(), null, e.confidence()));
    for (Inferred e : premises) {
      String sk = heads.get(e.source())[0];
      String tk = heads.get(e.target())[0];
      if (e.type().equals("attributed-to") && ATTRIBUTION_TARGETS.contains(tk))
        attributedTo.computeIfAbsent(e.source(), k -> new LinkedHashMap<>()).putIfAbsent(e.target(), e.confidence());
      if (e.type().equals("uses") && ATTRIBUTION_TARGETS.contains(sk))
        attributedTo.computeIfAbsent(e.target(), k -> new LinkedHashMap<>()).putIfAbsent(e.source(), e.confidence());
    }
    for (Edge e : explicit)
      if (e.type().equals("based-on") && "indicator".equals(e.sourceKind()))
        attributedTo.getOrDefault(e.target(), Map.of()).forEach((actor, confidence) ->
            want.accept(new Inferred(e.source(), actor, "indicates", "indicator-propagation", min(confidence, e.confidence()))));

    // Apply the difference.
    Map<List<Object>, Edge> existing = new HashMap<>();
    for (Edge e : edges) if (e.inferredBy() != null) existing.put(List.of(e.source(), e.target(), e.type()), e);
    int added = 0;
    int retracted = 0;
    for (var entry : desired.entrySet()) {
      Inferred edge = entry.getValue();
      Edge current = existing.remove(entry.getKey());
      if (current != null) {
        if (!Objects.equals(current.inferredBy(), edge.rule()) || !Objects.equals(current.confidence(), edge.confidence()))
          jdbc.update("UPDATE cti_relationships SET inferred_by = ?, confidence = ?, updated_at = now() WHERE owner_id = ? AND id = ?",
              edge.rule(), edge.confidence(), owner, current.id());
        continue;
      }
      String[] from = heads.get(edge.source());
      String[] to = heads.get(edge.target());
      if (!taxonomy.relationshipAllowed(edge.type(), from[0], to[0])) continue;
      UUID id = UUID.randomUUID();
      int inserted = jdbc.update(
          "INSERT INTO cti_relationships (owner_id, id, source_id, target_id, type, confidence, description, tlp, source, inferred_by)"
              + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (owner_id, source_id, target_id, type) DO NOTHING",
          owner, id, edge.source(), edge.target(), edge.type(), edge.confidence(), "Inferred by rule " + edge.rule(),
          CtiTaxonomy.stricterTlp(from[2], to[2]), source, edge.rule());
      if (inserted == 1) {
        added++;
        change(owner, edge.source(), from[0], from[1], "inferred",
            Map.of("type", edge.type(), "targetId", edge.target().toString(), "targetName", to[1], "rule", edge.rule()), source);
        after.add(() -> graph.upsertRelationship(owner, id, edge.source(), edge.target(), edge.type()));
      }
    }
    for (Edge stale : existing.values()) {
      jdbc.update("DELETE FROM cti_relationships WHERE owner_id = ? AND id = ?", owner, stale.id());
      retracted++;
      change(owner, stale.source(), stale.sourceKind(), stale.sourceName(), "retracted",
          Map.of("type", stale.type(), "targetId", stale.target().toString(), "targetName", stale.targetName(), "rule", stale.inferredBy()), source);
      after.add(() -> graph.deleteRelationship(owner, stale.id()));
    }
    return Map.of("added", added, "retracted", retracted);
  }

  private static UUID find(Map<UUID, UUID> parent, UUID node) {
    parent.putIfAbsent(node, node);
    UUID root = node;
    while (!parent.get(root).equals(root)) root = parent.get(root);
    while (!parent.get(node).equals(root)) {
      UUID next = parent.get(node);
      parent.put(node, root);
      node = next;
    }
    return root;
  }

  private static void union(Map<UUID, UUID> parent, UUID a, UUID b) {
    UUID ra = find(parent, a);
    UUID rb = find(parent, b);
    if (!ra.equals(rb)) parent.put(ra, rb);
  }

  private static Integer min(Integer left, Integer right) {
    if (left == null) return right;
    if (right == null) return left;
    return Math.min(left, right);
  }

  /** Re-runs inference for the owner, e.g. after a rule change. */
  public Map<String, Integer> reinfer(long owner) {
    List<Runnable> after = new ArrayList<>();
    Map<String, Integer> result = tx.execute(status -> infer(owner, "inference", after));
    after.forEach(Runnable::run);
    return result;
  }

  // ------------------------------------------------------------------ notes and opinions

  public Map<String, Object> addNote(long owner, UUID objectId, NoteInput input) {
    return tx.execute(status -> {
      Map<String, Object> object = head(owner, objectId);
      String[] valid = note(input, (String) object.get("tlp"));
      UUID id = UUID.randomUUID();
      jdbc.update("INSERT INTO cti_notes (owner_id, id, object_id, kind, opinion, body, tlp) VALUES (?, ?, ?, ?, ?, ?, ?)",
          owner, id, objectId, valid[0], valid[1], valid[2], valid[3]);
      change(owner, objectId, (String) object.get("kind"), (String) object.get("name"),
          "opinion".equals(valid[0]) ? "opinion-added" : "note-added", valid[1] == null ? Map.of() : Map.of("opinion", valid[1]), "manual");
      return note(owner, id);
    });
  }

  public Map<String, Object> updateNote(long owner, UUID id, NoteInput input) {
    if (input.revision() == null) throw bad("CTI_REVISION_REQUIRED");
    return tx.execute(status -> {
      var rows = jdbc.queryForList("SELECT n.object_id, n.kind, n.revision, o.kind AS object_kind, o.name, o.tlp FROM cti_notes n"
          + " JOIN cti_objects o ON o.owner_id = n.owner_id AND o.id = n.object_id WHERE n.owner_id = ? AND n.id = ? FOR UPDATE OF n", owner, id);
      if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
      var row = rows.get(0);
      if (((Number) row.get("revision")).longValue() != input.revision())
        throw new ResponseStatusException(HttpStatus.CONFLICT, "CTI_STALE_REVISION");
      if (input.kind() != null && !input.kind().equals(row.get("kind"))) throw bad("CTI_KIND_IMMUTABLE");
      String[] valid = note(new NoteInput((String) row.get("kind"), input.body(), input.opinion(), input.tlp(), null), (String) row.get("tlp"));
      jdbc.update("UPDATE cti_notes SET opinion = ?, body = ?, tlp = ?, revision = revision + 1, updated_at = now() WHERE owner_id = ? AND id = ?",
          valid[1], valid[2], valid[3], owner, id);
      change(owner, (UUID) row.get("object_id"), (String) row.get("object_kind"), (String) row.get("name"), "note-updated", Map.of(), "manual");
      return note(owner, id);
    });
  }

  public void deleteNote(long owner, UUID id) {
    tx.executeWithoutResult(status -> {
      var rows = jdbc.queryForList("DELETE FROM cti_notes n USING cti_objects o WHERE n.owner_id = ? AND n.id = ?"
          + " AND o.owner_id = n.owner_id AND o.id = n.object_id RETURNING o.id, o.kind, o.name", owner, id);
      if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
      change(owner, (UUID) rows.get(0).get("id"), (String) rows.get(0).get("kind"), (String) rows.get(0).get("name"), "note-deleted", Map.of(), "manual");
    });
  }

  /** Adds a note unless the record already has one of the same kind, opinion and text (idempotent imports). */
  boolean addNoteIfAbsent(long owner, UUID objectId, NoteInput input) {
    String[] valid = note(input, (String) head(owner, objectId).get("tlp"));
    boolean present = !jdbc.queryForList("SELECT 1 FROM cti_notes WHERE owner_id = ? AND object_id = ? AND kind = ?"
        + " AND opinion IS NOT DISTINCT FROM ? AND body = ?", owner, objectId, valid[0], valid[1], valid[2]).isEmpty();
    if (present) return false;
    addNote(owner, objectId, input);
    return true;
  }

  /** Validated [kind, opinion, body, tlp]. */
  private static String[] note(NoteInput input, String objectTlp) {
    String kind = input.kind() == null ? "note" : input.kind();
    if (!Set.of("note", "opinion").contains(kind)) throw bad("CTI_INVALID_NOTE_KIND");
    String body = input.body() == null ? "" : input.body().trim();
    if (body.isEmpty() && "note".equals(kind)) throw bad("CTI_NOTE_BODY_REQUIRED");
    if (body.length() > 20000) throw bad("CTI_NOTE_TOO_LONG");
    String opinion = "opinion".equals(kind) ? input.opinion() : null;
    if ("opinion".equals(kind) && (opinion == null || !OPINIONS.contains(opinion))) throw bad("CTI_INVALID_OPINION");
    if ("note".equals(kind) && input.opinion() != null && !input.opinion().isBlank()) throw bad("CTI_INVALID_OPINION");
    String tlp = input.tlp() == null || input.tlp().isBlank() ? objectTlp : CtiTaxonomy.tlp(input.tlp());
    return new String[] {kind, opinion, body, tlp};
  }

  private Map<String, Object> note(long owner, UUID id) {
    return notes(owner, null, id).get(0);
  }

  List<Map<String, Object>> notes(long owner, UUID objectId) {
    return notes(owner, objectId, null);
  }

  private List<Map<String, Object>> notes(long owner, UUID objectId, UUID noteId) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList("SELECT id, object_id, kind, opinion, body, tlp, revision, created_at, updated_at FROM cti_notes"
        + " WHERE owner_id = ? AND " + (noteId == null ? "object_id = ?" : "id = ?") + " ORDER BY created_at DESC LIMIT 500",
        owner, noteId == null ? objectId : noteId)) {
      Map<String, Object> note = new LinkedHashMap<>();
      note.put("id", row.get("id"));
      note.put("objectId", row.get("object_id"));
      note.put("kind", row.get("kind"));
      note.put("opinion", row.get("opinion"));
      note.put("body", row.get("body"));
      note.put("tlp", row.get("tlp"));
      note.put("revision", ((Number) row.get("revision")).longValue());
      note.put("createdAt", iso(row.get("created_at")));
      note.put("updatedAt", iso(row.get("updated_at")));
      out.add(note);
    }
    return out;
  }

  /** Every note of the owner, for STIX export. */
  List<Map<String, Object>> allNotes(long owner) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList("SELECT id FROM cti_notes WHERE owner_id = ? ORDER BY created_at, id", owner))
      out.add(note(owner, (UUID) row.get("id")));
    return out;
  }

  // ------------------------------------------------------------------ sightings

  public Map<String, Object> addSighting(long owner, UUID objectId, SightingInput input, String source) {
    List<Runnable> after = new ArrayList<>();
    Map<String, Object> result = tx.execute(status -> {
      UUID id = recordSighting(owner, objectId, input, source(source));
      return Map.<String, Object>of("id", id == null ? "" : id.toString(), "recorded", id != null);
    });
    after.forEach(Runnable::run);
    return result;
  }

  /** Inserts one sighting; returns null when the identical report already exists. */
  private UUID recordSighting(long owner, UUID objectId, SightingInput input, String source) {
    Map<String, Object> object = head(owner, objectId);
    if (!SIGHTABLE.contains((String) object.get("kind"))) throw bad("CTI_NOT_SIGHTABLE");
    Instant first = CtiValues.instant(input.firstSeen());
    Instant last = CtiValues.instant(input.lastSeen());
    if (first == null && last == null) first = last = Instant.now();
    if (first == null) first = last;
    if (last == null) last = first;
    if (first.isAfter(last)) throw bad("CTI_INVALID_TIMEFRAME");
    if (last.isAfter(Instant.now().plusSeconds(86400))) throw bad("CTI_SIGHTING_IN_FUTURE");
    int count = input.count() == null ? 1 : input.count();
    if (count < 1 || count > 1_000_000_000) throw bad("CTI_INVALID_SIGHTING_COUNT");
    String where = input.where() == null ? "" : input.where().trim();
    if (where.length() > 256) throw bad("CTI_SIGHTING_WHERE_TOO_LONG");
    List<String> observed = new ArrayList<>();
    if (input.observed() != null) for (String value : input.observed()) {
      if (value == null || value.isBlank()) continue;
      if (value.length() > 2048 || observed.size() >= 100) throw bad("CTI_SIGHTING_OBSERVED_TOO_LARGE");
      observed.add(CtiValues.refang(value));
    }
    UUID id = UUID.randomUUID();
    int inserted = jdbc.update(
        "INSERT INTO cti_sightings (owner_id, id, object_id, first_seen, last_seen, count, where_sighted, source, confidence,"
            + " description, observed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb))"
            + " ON CONFLICT (owner_id, object_id, where_sighted, source, first_seen, last_seen) DO NOTHING",
        owner, id, objectId, Timestamp.from(first), Timestamp.from(last), count, where, source, confidence(input.confidence()),
        description(input.description()), text(observed));
    if (inserted == 0) return null;
    jdbc.update("UPDATE cti_objects SET first_seen = least(first_seen, ?), last_seen = greatest(last_seen, ?), updated_at = now()"
        + " WHERE owner_id = ? AND id = ?", Timestamp.from(first), Timestamp.from(last), owner, objectId);
    change(owner, objectId, (String) object.get("kind"), (String) object.get("name"), "sighted",
        Map.of("count", count, "where", where, "lastSeen", last.toString()), source);
    return id;
  }

  public void deleteSighting(long owner, UUID id) {
    tx.executeWithoutResult(status -> {
      var rows = jdbc.queryForList("DELETE FROM cti_sightings s USING cti_objects o WHERE s.owner_id = ? AND s.id = ?"
          + " AND o.owner_id = s.owner_id AND o.id = s.object_id RETURNING o.id, o.kind, o.name", owner, id);
      if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
      change(owner, (UUID) rows.get(0).get("id"), (String) rows.get(0).get("kind"), (String) rows.get(0).get("name"),
          "sighting-deleted", Map.of(), "manual");
    });
  }

  List<Map<String, Object>> sightings(long owner, UUID objectId) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList("SELECT id, object_id, first_seen, last_seen, count, where_sighted, source, confidence,"
        + " description, observed::text AS observed, created_at FROM cti_sightings WHERE owner_id = ?"
        + (objectId == null ? "" : " AND object_id = ?") + " ORDER BY last_seen DESC LIMIT " + (objectId == null ? "100000" : "200"),
        objectId == null ? new Object[] {owner} : new Object[] {owner, objectId})) {
      Map<String, Object> sighting = new LinkedHashMap<>();
      sighting.put("id", row.get("id"));
      sighting.put("objectId", row.get("object_id"));
      sighting.put("firstSeen", iso(row.get("first_seen")));
      sighting.put("lastSeen", iso(row.get("last_seen")));
      sighting.put("count", ((Number) row.get("count")).intValue());
      sighting.put("where", row.get("where_sighted"));
      sighting.put("source", row.get("source"));
      sighting.put("confidence", row.get("confidence"));
      sighting.put("description", row.get("description"));
      sighting.put("observed", read((String) row.get("observed")));
      sighting.put("createdAt", iso(row.get("created_at")));
      out.add(sighting);
    }
    return out;
  }

  // ------------------------------------------------------------------ ATT&CK

  /** Which records use which ATT&CK technique, for the matrix view. */
  public Map<String, Object> attackUsage(long owner) {
    Map<String, List<Map<String, Object>>> usage = new TreeMap<>();
    for (var row : jdbc.queryForList(
        "SELECT o.id, o.kind, o.name, o.status, t.value AS technique FROM cti_objects o,"
            + " jsonb_array_elements_text(CASE WHEN jsonb_typeof(o.attributes->'ttps') = 'array' THEN o.attributes->'ttps' ELSE '[]'::jsonb END) t(value)"
            + " WHERE o.owner_id = ? ORDER BY lower(o.name)", owner))
      usage.computeIfAbsent((String) row.get("technique"), k -> new ArrayList<>()).add(
          Map.of("id", row.get("id"), "kind", row.get("kind"), "name", row.get("name"), "status", row.get("status")));
    return Map.of("usage", usage);
  }

  CtiTaxonomy.Kind taxonomyKind(String kind) {
    return taxonomy.kind(kind);
  }

  /** The record with this kind and (already normalized) dedupe key, or null. */
  Map<String, Object> findByNaturalKey(long owner, String kind, String key) {
    return findByKey(owner, kind, key, false);
  }

  /** True when a record with this kind and dedupe key exists. */
  boolean exists(long owner, String kind, String key) {
    return findByKey(owner, kind, CtiValues.normalizeKey(key), false) != null;
  }

  // ------------------------------------------------------------------ helpers

  Candidate prepare(String kindId, String name, String status, String tlp, Integer confidence, String description,
      JsonNode attributes, List<String> labels, String firstSeen, String lastSeen, JsonNode existingAttributes) {
    CtiTaxonomy.Kind kind = taxonomy.kind(kindId);
    ObjectNode clean = CtiValues.attributes(kind, attributes, existingAttributes, false);
    if ("victim".equals(kind.id()) && !clean.has("redacted")) clean.put("redacted", true);
    boolean nameGiven = name != null && !name.isBlank();
    String resolved = nameGiven ? name.trim().replaceAll("\\s+", " ") : CtiValues.defaultName(kind.id(), clean).trim();
    if (resolved.isBlank()) throw bad("CTI_NAME_REQUIRED");
    if (resolved.length() > 512) throw bad("CTI_NAME_TOO_LONG");
    boolean statusGiven = status != null && !status.isBlank();
    if (statusGiven && !kind.statuses().contains(status)) throw bad("CTI_INVALID_STATUS");
    boolean tlpGiven = tlp != null && !tlp.isBlank();
    String resolvedTlp = tlpGiven ? CtiTaxonomy.tlp(tlp) : kind.privateKind() ? "red" : taxonomy.defaultTlp();
    Instant first = CtiValues.instant(firstSeen);
    Instant last = CtiValues.instant(lastSeen);
    if (first != null && last != null && first.isAfter(last)) throw bad("CTI_INVALID_TIMEFRAME");
    return new Candidate(kind, resolved, nameGiven, CtiValues.naturalKey(kind, resolved, clean),
        statusGiven ? status : kind.statuses().get(0), statusGiven, resolvedTlp, tlpGiven, confidence(confidence),
        description(description), clean, CtiValues.labels(labels), first, last);
  }

  private static Integer confidence(Integer value) {
    if (value != null && (value < 0 || value > 100)) throw bad("CTI_INVALID_CONFIDENCE");
    return value;
  }

  private static String description(String value) {
    String out = value == null ? "" : value.trim();
    if (out.length() > 20000) throw bad("CTI_DESCRIPTION_TOO_LONG");
    return out;
  }

  private static String source(String value) {
    String out = value == null || value.isBlank() ? "manual" : value.trim();
    if (out.length() > 256 || !out.matches("^[\\p{Alnum} :._/@#+-]+$")) throw bad("CTI_INVALID_SOURCE");
    return out;
  }

  private void quota(long owner) {
    Long count = jdbc.queryForObject("SELECT count(*) FROM cti_objects WHERE owner_id = ?", Long.class, owner);
    if (count != null && count >= MAX_OBJECTS_PER_OWNER)
      throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "CTI_QUOTA_EXCEEDED");
  }

  private String insertSql() {
    return "INSERT INTO cti_objects (owner_id, id, kind, name, natural_key, status, tlp, confidence, description,"
        + " attributes, labels, first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb),"
        + " CAST(? AS jsonb), ?, ?, ?)";
  }

  private Object[] insertArgs(long owner, UUID id, Candidate c, String source) {
    return new Object[] {owner, id, c.kind().id(), c.name(), c.naturalKey(), c.status(), c.tlp(), c.confidence(),
        c.description(), text(c.attributes()), text(c.labels()), ts(c.firstSeen()), ts(c.lastSeen()), source};
  }

  private UUID insert(long owner, Candidate c, String source) {
    UUID id = UUID.randomUUID();
    jdbc.update(insertSql(), insertArgs(owner, id, c, source));
    return id;
  }

  private void write(long owner, UUID id, Candidate c) {
    jdbc.update(
        "UPDATE cti_objects SET name = ?, natural_key = ?, status = ?, tlp = ?, confidence = ?, description = ?,"
            + " attributes = CAST(? AS jsonb), labels = CAST(? AS jsonb), first_seen = ?, last_seen = ?,"
            + " revision = revision + 1, updated_at = now() WHERE owner_id = ? AND id = ?",
        c.name(), c.naturalKey(), c.status(), c.tlp(), c.confidence(), c.description(), text(c.attributes()),
        text(c.labels()), ts(c.firstSeen()), ts(c.lastSeen()), owner, id);
  }

  /**
   * Field-level diff for the change journal: {@code fields} lists what changed and {@code changes}
   * holds each field's old and new value. Attributes are diffed per key ({@code attributes.value}).
   * Long text is truncated so the journal stays bounded.
   */
  Map<String, Object> diff(Map<String, Object> existing, Candidate c) {
    Map<String, Object> changes = new LinkedHashMap<>();
    compare(changes, "name", existing.get("name"), c.name());
    compare(changes, "status", existing.get("status"), c.status());
    compare(changes, "tlp", existing.get("tlp"), c.tlp());
    compare(changes, "confidence", existing.get("confidence"), c.confidence());
    compare(changes, "description", existing.get("description"), c.description());
    JsonNode before = (JsonNode) existing.get("attributes");
    Set<String> keys = new TreeSet<>();
    before.fieldNames().forEachRemaining(keys::add);
    c.attributes().fieldNames().forEachRemaining(keys::add);
    for (String key : keys) {
      JsonNode was = before.get(key);
      JsonNode now = c.attributes().get(key);
      if (!Objects.equals(was, now)) compare(changes, "attributes." + key, was, now);
    }
    compare(changes, "labels", strings((JsonNode) existing.get("labels")), c.labels());
    compare(changes, "firstSeen", existing.get("firstSeen"), c.firstSeen() == null ? null : c.firstSeen().toString());
    compare(changes, "lastSeen", existing.get("lastSeen"), c.lastSeen() == null ? null : c.lastSeen().toString());
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("fields", new ArrayList<>(changes.keySet()));
    out.put("changes", changes);
    return out;
  }

  private void compare(Map<String, Object> changes, String field, Object before, Object after) {
    if (Objects.equals(before, after)) return;
    Map<String, Object> pair = new LinkedHashMap<>();
    pair.put("from", bounded(before));
    pair.put("to", bounded(after));
    changes.put(field, pair);
  }

  private Object bounded(Object value) {
    if (value == null) return null;
    if (value instanceof JsonNode node) {
      if (node.isTextual()) return bounded(node.asText());
      if (node.isArray()) return bounded(strings(node));
      return node;
    }
    if (value instanceof String text) return text.length() > 300 ? text.substring(0, 299) + "…" : text;
    if (value instanceof List<?> list) return list.size() > 50 ? List.copyOf(list.subList(0, 50)) : list;
    return value;
  }

  private Runnable project(long owner, UUID id, Candidate c) {
    return () -> graph.upsertObject(owner, id, c.kind().id(), c.name(), c.tlp(), c.status());
  }

  private Map<String, Object> findByKey(long owner, String kind, String key, boolean forUpdate) {
    var rows = jdbc.queryForList("SELECT " + COLUMNS + " FROM cti_objects WHERE owner_id = ? AND kind = ? AND natural_key = ?"
        + (forUpdate ? " FOR UPDATE" : ""), owner, kind, key);
    return rows.isEmpty() ? null : row(rows.get(0));
  }

  private Map<String, Object> lock(long owner, UUID id) {
    var rows = jdbc.queryForList("SELECT " + COLUMNS + " FROM cti_objects WHERE owner_id = ? AND id = ? FOR UPDATE", owner, id);
    if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    return row(rows.get(0));
  }

  private Map<String, Object> head(long owner, UUID id) {
    var rows = jdbc.queryForList("SELECT id, kind, name, tlp FROM cti_objects WHERE owner_id = ? AND id = ?", owner, id);
    if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    return rows.get(0);
  }

  private void change(long owner, UUID objectId, String kind, String name, String action, Map<String, ?> detail, String source) {
    jdbc.update("INSERT INTO cti_changes (owner_id, object_id, kind, name, action, detail, source) VALUES (?, ?, ?, ?, ?, CAST(? AS jsonb), ?)",
        owner, objectId, kind, name, action, text(detail), source);
  }

  private Map<String, Object> row(Map<String, Object> row) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", row.get("id"));
    out.put("kind", row.get("kind"));
    out.put("name", row.get("name"));
    out.put("naturalKey", row.get("natural_key"));
    out.put("status", row.get("status"));
    out.put("tlp", row.get("tlp"));
    Integer confidence = row.get("confidence") == null ? null : ((Number) row.get("confidence")).intValue();
    out.put("confidence", confidence);
    out.put("description", row.get("description"));
    out.put("attributes", read((String) row.get("attributes")));
    out.put("labels", read((String) row.get("labels")));
    out.put("firstSeen", iso(row.get("first_seen")));
    out.put("lastSeen", iso(row.get("last_seen")));
    out.put("source", row.get("source"));
    out.put("revision", ((Number) row.get("revision")).longValue());
    out.put("createdAt", iso(row.get("created_at")));
    out.put("updatedAt", iso(row.get("updated_at")));
    if (row.containsKey("score")) {
      out.put("score", row.get("score") == null ? null : ((Number) row.get("score")).intValue());
      out.put("lastSighted", iso(row.get("last_sighted")));
      out.put("sightingCount", row.get("sightings") == null ? 0L : ((Number) row.get("sightings")).longValue());
      if (row.get("half_life") != null) out.put("halfLifeDays", ((Number) row.get("half_life")).intValue());
    }
    return out;
  }

  private JsonNode read(String value) {
    try {
      return value == null ? json.createObjectNode() : json.readTree(value);
    } catch (JsonProcessingException failure) {
      throw new IllegalStateException(failure);
    }
  }

  private String text(Object value) {
    try {
      return json.writeValueAsString(value);
    } catch (JsonProcessingException failure) {
      throw new IllegalStateException(failure);
    }
  }

  static List<String> strings(JsonNode node) {
    List<String> out = new ArrayList<>();
    if (node != null) node.forEach(item -> out.add(item.asText()));
    return out;
  }

  static String iso(Object value) {
    if (value == null) return null;
    if (value instanceof Timestamp stamp) return stamp.toInstant().toString();
    if (value instanceof java.time.OffsetDateTime offset) return offset.toInstant().toString();
    return value.toString();
  }

  private static Timestamp ts(Instant value) {
    return value == null ? null : Timestamp.from(value);
  }

  private static Timestamp timestamp(String value) {
    return value == null ? null : Timestamp.from(Instant.parse(value));
  }

  private static Instant min(Instant left, Instant right) {
    if (left == null) return right;
    if (right == null) return left;
    return left.isBefore(right) ? left : right;
  }

  private static Instant maxInstant(Instant left, Instant right) {
    if (left == null) return right;
    if (right == null) return left;
    return left.isAfter(right) ? left : right;
  }

  private static Integer max(Integer left, Integer right) {
    if (left == null) return right;
    if (right == null) return left;
    return Math.max(left, right);
  }

}
