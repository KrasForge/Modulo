package com.modulo.cti;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.modulo.remote.RemoteCredentialStore;
import com.modulo.remote.SafeHttpFetcher;
import com.modulo.security.AuthenticatedUserService;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;

/** Enrichment connectors and the TAXII 2.1 server and client. */
@Testcontainers
class CtiConnectivityTest {
  @Container
  static final PostgreSQLContainer<?> database = new PostgreSQLContainer<>(org.testcontainers.utility.DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

  static DriverManagerDataSource source;
  final ObjectMapper json = new ObjectMapper();
  JdbcTemplate jdbc;
  CtiService cti;
  CtiExportService exports;
  RemoteCredentialStore credentials;
  final List<String> requests = new ArrayList<>();
  final List<Map<String, String>> requestHeaders = new ArrayList<>();
  final Map<String, SafeHttpFetcher.Response> responses = new LinkedHashMap<>();

  @BeforeAll
  static void migrate() {
    source = new DriverManagerDataSource(database.getJdbcUrl(), database.getUsername(), database.getPassword());
    Flyway.configure().dataSource(source).locations("classpath:db/postgresql").load().migrate();
  }

  @BeforeEach
  void setup() {
    jdbc = new JdbcTemplate(source);
    jdbc.execute("TRUNCATE users CASCADE");
    jdbc.update("INSERT INTO users(id,username) VALUES(1,'one'),(2,'two')");
    CtiTaxonomy taxonomy = new CtiTaxonomy();
    cti = new CtiService(jdbc, json, taxonomy, new CtiGraphProjection(Optional.empty()), new DataSourceTransactionManager(source));
    exports = new CtiExportService(cti, taxonomy, new CtiAttackLibrary(), json);
    AuthenticatedUserService users = mock(AuthenticatedUserService.class);
    when(users.requireUserId()).thenReturn(1L);
    credentials = new RemoteCredentialStore(jdbc, users, Base64.getEncoder().encodeToString(new byte[32]));
    requests.clear();
    requestHeaders.clear();
    responses.clear();
  }

  SafeHttpFetcher.Response fetch(String url, Map<String, String> headers) {
    requests.add(url);
    requestHeaders.add(headers);
    for (var entry : responses.entrySet()) if (url.startsWith(entry.getKey())) return entry.getValue();
    throw new AssertionError("Unexpected request " + url);
  }

  static SafeHttpFetcher.Response ok(String body) {
    return ok(body, Map.of());
  }

  static SafeHttpFetcher.Response ok(String body, Map<String, String> headers) {
    return new SafeHttpFetcher.Response(200, "application/json", body.getBytes(StandardCharsets.UTF_8), URI.create("https://example.test"), headers);
  }

  ObjectNode attrs(Object... pairs) {
    ObjectNode node = json.createObjectNode();
    for (int i = 0; i < pairs.length; i += 2) node.set((String) pairs[i], json.valueToTree(pairs[i + 1]));
    return node;
  }

  UUID create(long owner, String kind, String name, String tlp, ObjectNode attributes) {
    return (UUID) cti.create(owner, new CtiService.ObjectInput(kind, name, null, tlp, null, null, attributes, null, null, null, null), "manual").get("id");
  }

  @SuppressWarnings("unchecked")
  List<Map<String, Object>> rels(UUID id) {
    return (List<Map<String, Object>>) cti.detail(1, id).get("relationships");
  }

  // ------------------------------------------------------------------ enrichment

  @Test
  @SuppressWarnings("unchecked")
  void connectorsLogLookupsLinkFindingsAndAvoidRepeatedWork() {
    CtiEnrichmentService enrichment = new CtiEnrichmentService(cti, credentials, this::fetch);
    UUID domain = create(1, "infrastructure", null, "amber", attrs("infraKind", "blob-host", "value", "example.ink"));
    var options = (List<Map<String, Object>>) enrichment.options(1, domain).get("providers");
    assertEquals(List.of("crt.sh", "urlscan", "passive-dns"), options.stream().map(o -> o.get("provider")).toList());

    responses.put("https://crt.sh/", ok("[{\"name_value\":\"cdn7.example.ink\\n*.example.ink\",\"not_before\":\"2026-10-01T00:00:00\","
        + "\"issuer_name\":\"C=US, O=Let's Encrypt, CN=R10\"},{\"name_value\":\"evil.other.com\",\"not_before\":\"2026-11-01T00:00:00\"}]"));
    var result = enrichment.enrich(1, domain, "crt.sh", false);
    assertEquals("done", result.get("status"));
    assertEquals(1, result.get("created"), "cdn7 is new; the apex and foreign names are not findings");
    assertTrue(((String) result.get("summary")).startsWith("2 certificates, 1 other hostnames"));
    assertTrue(requests.get(0).startsWith("https://crt.sh/?q=%25.example.ink&output=json"));
    assertTrue(rels(domain).stream().anyMatch(r -> "related-to".equals(r.get("type")) && "cdn7.example.ink".equals(((Map<?, ?>) r.get("other")).get("name"))));
    assertTrue(rels(domain).stream().anyMatch(r -> "enriches".equals(r.get("type"))));

    assertEquals(true, enrichment.enrich(1, domain, "crt.sh", false).get("reused"), "a repeat within ten minutes is not re-run");
    assertEquals(1, requests.size());
    enrichment.enrich(1, domain, "crt.sh", true);
    assertEquals(2, requests.size());

    responses.put("https://api.mnemonic.no/", ok("{\"data\":[{\"query\":\"example.ink\",\"answer\":\"203.0.113.7\",\"rrtype\":\"a\","
        + "\"firstSeenTimestamp\":1760000000000,\"lastSeenTimestamp\":1762000000000}]}"));
    enrichment.enrich(1, domain, "passive-dns", false);
    var resolution = rels(domain).stream().filter(r -> "resolves-to".equals(r.get("type"))).findFirst().orElseThrow();
    assertEquals("203.0.113.7", ((Map<?, ?>) resolution.get("other")).get("name"));
    assertNotNull(resolution.get("firstSeen"));

    responses.put("https://urlscan.io/", new SafeHttpFetcher.Response(500, "text/plain", new byte[0], URI.create("https://urlscan.io")));
    var failed = enrichment.enrich(1, domain, "urlscan", false);
    assertEquals("failed", failed.get("status"));
    assertEquals("Lookup failed: CTI_PROVIDER_ERROR_500", failed.get("summary"));

    credentials.set("urlscanApiKey", "secret-key");
    responses.put("https://urlscan.io/", ok("{\"results\":[{\"page\":{\"ip\":\"198.51.100.4\",\"domain\":\"example.ink\",\"asn\":\"AS64500\","
        + "\"asnname\":\"EXAMPLE\",\"country\":\"NL\"},\"task\":{\"time\":\"2026-11-12T10:00:00Z\"}}]}"));
    var scanned = enrichment.enrich(1, domain, "urlscan", false);
    assertEquals("done", scanned.get("status"), "a failed lookup is not reused");
    assertEquals("secret-key", requestHeaders.get(requestHeaders.size() - 1).get("API-Key"));

    UUID wallet = create(1, "identity", null, "amber", attrs("identityType", "wallet", "value", "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf"));
    responses.put("https://apilist.tronscanapi.com/", ok("{\"balance\":12500000,\"totalTransactionCount\":42,\"date_created\":1700000000000}"));
    var tron = enrichment.enrich(1, wallet, "blockchain-explorer", false);
    assertEquals("TRON balance 12.5 TRX, 42 transactions, created 2023-11-14", tron.get("summary"));
    assertEquals("CTI_PROVIDER_NOT_APPLICABLE",
        assertThrows(ResponseStatusException.class, () -> enrichment.enrich(1, wallet, "crt.sh", false)).getReason());
  }

  // ------------------------------------------------------------------ TAXII server

  @Test
  @SuppressWarnings("unchecked")
  void taxiiServerScopesTokensToOneTlpCappedCollection() throws Exception {
    CtiTaxiiService taxii = new CtiTaxiiService(jdbc, exports, credentials, this::fetch);
    MockMvc mvc = MockMvcBuilders.standaloneSetup(new TaxiiController(taxii, "https://modulo.example"))
        .defaultRequest(get("/").accept(MediaType.ALL)).build();
    create(1, "actor", "TronzitVeca", "green", attrs());
    create(1, "indicator", null, "green", attrs("indicatorType", "domain", "value", "evil.example.ink"));
    create(1, "infrastructure", null, "red", attrs("infraKind", "c2", "value", "198.51.100.9"));
    var collection = taxii.createCollection(1, new CtiTaxiiService.CollectionInput("Partners", null, "green", false, true, false));
    UUID collectionId = (UUID) collection.get("id");
    var token = taxii.createToken(1, collectionId, new CtiTaxiiService.TokenInput("SEAL"));
    String basic = "Basic " + Base64.getEncoder().encodeToString((token.get("username") + ":" + token.get("password")).getBytes(StandardCharsets.UTF_8));
    String bearer = "Bearer " + token.get("bearer");
    String root = "/api/taxii2/root/collections/" + collectionId + "/";

    mvc.perform(get("/api/taxii2/")).andExpect(status().isOk())
        .andExpect(header().string("Content-Type", CtiTaxiiService.MEDIA_TYPE))
        .andExpect(jsonPath("$.default").value("https://modulo.example/api/taxii2/root/"));
    mvc.perform(get("/api/taxii2/root/collections/")).andExpect(status().isUnauthorized())
        .andExpect(header().string("WWW-Authenticate", "Basic realm=\"Modulo TAXII\""));
    mvc.perform(get("/api/taxii2/root/collections/").header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
        (token.get("username") + ":wrong").getBytes(StandardCharsets.UTF_8)))).andExpect(status().isUnauthorized());
    mvc.perform(get("/api/taxii2/root/collections/").header("Authorization", bearer))
        .andExpect(status().isOk()).andExpect(jsonPath("$.collections[0].title").value("Partners"))
        .andExpect(jsonPath("$.collections[0].can_write").value(false));
    mvc.perform(get("/api/taxii2/root/collections/" + UUID.randomUUID() + "/objects/").header("Authorization", basic))
        .andExpect(status().isNotFound());

    List<Map<String, Object>> all = taxii.collectionObjects(taxii.authenticate(basic).orElseThrow());
    assertFalse(json.writeValueAsString(all).contains("198.51.100.9"), "red records stay out of a green collection");
    String page = mvc.perform(get(root + "objects/").param("limit", "2").header("Authorization", basic))
        .andExpect(status().isOk()).andExpect(jsonPath("$.more").value(true)).andExpect(jsonPath("$.next").value("2"))
        .andExpect(header().exists("X-TAXII-Date-Added-Last")).andReturn().getResponse().getContentAsString();
    assertEquals(2, json.readTree(page).path("objects").size());
    mvc.perform(get(root + "objects/").param("next", "2").param("limit", "500").header("Authorization", basic))
        .andExpect(status().isOk()).andExpect(jsonPath("$.more").value(false));
    mvc.perform(get(root + "objects/").param("match[type]", "indicator").header("Authorization", basic))
        .andExpect(jsonPath("$.objects.length()").value(1)).andExpect(jsonPath("$.objects[0].pattern").value("[domain-name:value = 'evil.example.ink']"));
    String last = CtiTaxiiService.dateAdded(all.get(all.size() - 1));
    mvc.perform(get(root + "objects/").param("added_after", last).header("Authorization", basic))
        .andExpect(jsonPath("$.objects.length()").value(0));
    mvc.perform(get(root + "manifest/").header("Authorization", basic))
        .andExpect(jsonPath("$.objects[0].media_type").value("application/stix+json;version=2.1"));
    String indicatorId = all.stream().filter(o -> "indicator".equals(o.get("type"))).findFirst().orElseThrow().get("id").toString();
    mvc.perform(get(root + "objects/" + indicatorId + "/").header("Authorization", basic)).andExpect(jsonPath("$.objects[0].id").value(indicatorId));
    mvc.perform(post(root + "objects/").header("Authorization", basic).contentType(CtiTaxiiService.MEDIA_TYPE).content("{\"objects\":[]}"))
        .andExpect(status().isForbidden());

    // A writable collection accepts objects through the idempotent import and reports a status.
    var inbox = taxii.createCollection(1, new CtiTaxiiService.CollectionInput("Inbox", null, "amber", false, false, true));
    var writer = taxii.createToken(1, (UUID) inbox.get("id"), null);
    String writerAuth = "Bearer " + writer.get("bearer");
    String envelope = json.writeValueAsString(Map.of("objects", List.of(Map.of("type", "indicator", "spec_version", "2.1",
        "id", "indicator--" + UUID.randomUUID(), "created", "2026-11-01T00:00:00.000Z", "modified", "2026-11-01T00:00:00.000Z",
        "pattern", "[ipv4-addr:value = '203.0.113.50']", "pattern_type", "stix", "valid_from", "2026-11-01T00:00:00.000Z"))));
    String status = mvc.perform(post("/api/taxii2/root/collections/" + inbox.get("id") + "/objects/").header("Authorization", writerAuth)
            .contentType(CtiTaxiiService.MEDIA_TYPE).content(envelope))
        .andExpect(status().isAccepted()).andExpect(jsonPath("$.success_count").value(1)).andReturn().getResponse().getContentAsString();
    mvc.perform(get("/api/taxii2/root/status/" + json.readTree(status).path("id").asText() + "/").header("Authorization", writerAuth))
        .andExpect(jsonPath("$.status").value("complete"));
    mvc.perform(get("/api/taxii2/root/collections/" + inbox.get("id") + "/objects/").header("Authorization", writerAuth))
        .andExpect(status().isForbidden());
    assertEquals(1L, cti.list(1, "indicator", null, "203.0.113.50", null, null, null, 0, 5).get("total"));

    taxii.revokeToken(1, (UUID) token.get("id"));
    mvc.perform(get("/api/taxii2/root/collections/").header("Authorization", basic)).andExpect(status().isUnauthorized());
    assertTrue(((List<Map<String, Object>>) taxii.collections(1).get(0).get("tokens")).get(0).get("revokedAt") != null);
  }

  // ------------------------------------------------------------------ TAXII client

  @Test
  void feedsPullPagesWithSealedCredentialsAndKeepACursor() throws Exception {
    CtiTaxiiService taxii = new CtiTaxiiService(jdbc, exports, credentials, this::fetch);
    // The "remote" server is owner 2's collection, served through the same export.
    create(2, "actor", "Remote actor", "green", attrs());
    create(2, "indicator", null, "green", attrs("indicatorType", "domain", "value", "remote.example.ink"));
    List<Object> objects = new ArrayList<>((List<?>) exports.stix(2, new CtiExportService.Options("green", false, null)).get("objects"));
    // An unmarked object takes the feed's default TLP.
    ObjectNode unmarked = json.createObjectNode().put("type", "threat-actor").put("spec_version", "2.1")
        .put("id", "threat-actor--" + UUID.randomUUID()).put("created", "2026-11-02T00:00:00.000Z").put("modified", "2026-11-02T00:00:00.000Z")
        .put("name", "Unmarked actor");
    objects.add(json.convertValue(unmarked, Map.class));
    String firstPage = json.writeValueAsString(Map.of("more", true, "next", "p2", "objects", objects.subList(0, 3)));
    String secondPage = json.writeValueAsString(Map.of("more", false, "objects", objects.subList(3, objects.size())));
    String base = "https://partner.example/taxii2/root/collections/feed-1/objects/";
    responses.put(base + "?limit=500&next=p2", ok(secondPage, Map.of("X-TAXII-Date-Added-Last", "2026-11-12T00:00:00.000Z")));
    responses.put(base + "?limit=500", ok(firstPage, Map.of("X-TAXII-Date-Added-Last", "2026-11-11T00:00:00.000Z")));

    var feed = taxii.createFeed(1, new CtiTaxiiService.FeedInput("Partner feed", "https://partner.example/taxii2/root",
        "feed-1", "modulo", "s3cret", "amber", 60, true));
    assertEquals(false, json.valueToTree(feed).has("password"));
    assertEquals(true, feed.get("hasPassword"));
    var pulled = taxii.pull(1, (UUID) feed.get("id"));
    assertEquals(2, pulled.get("pages"));
    assertEquals("2026-11-12T00:00:00.000Z", pulled.get("addedAfter"));
    assertEquals("Basic " + Base64.getEncoder().encodeToString("modulo:s3cret".getBytes(StandardCharsets.UTF_8)), requestHeaders.get(0).get("Authorization"));
    assertEquals(CtiTaxiiService.MEDIA_TYPE, requestHeaders.get(0).get("Accept"));
    assertEquals(3L, cti.list(1, null, null, null, null, null, null, 0, 10).get("total"));
    @SuppressWarnings("unchecked")
    var unmarkedActor = (Map<String, Object>) ((List<?>) cti.list(1, "actor", null, "Unmarked", null, null, null, 0, 1).get("items")).get(0);
    assertEquals("amber", unmarkedActor.get("tlp"));
    assertTrue(((String) unmarkedActor.get("source")).startsWith("taxii:"));

    // The next pull resumes from the cursor; the scheduler only polls feeds that are due.
    responses.clear();
    responses.put(base + "?limit=500&added_after=2026-11-12T00%3A00%3A00.000Z", ok("{\"more\":false,\"objects\":[]}"));
    jdbc.update("UPDATE cti_taxii_feeds SET last_polled_at = now() - interval '2 hours'");
    requests.clear();
    taxii.pollDue();
    assertEquals(1, requests.size());
    taxii.pollDue();
    assertEquals(1, requests.size(), "not due again for an hour");
    assertEquals("CTI_TAXII_API_ROOT_INVALID", assertThrows(ResponseStatusException.class, () ->
        taxii.createFeed(1, new CtiTaxiiService.FeedInput("x", "ftp://partner.example/", "c", null, null, null, null, null))).getReason());
    JsonNode stored = json.valueToTree(jdbc.queryForMap("SELECT encode(secret, 'hex') AS hex FROM cti_taxii_feeds LIMIT 1"));
    assertFalse(stored.path("hex").asText().contains(HexFormat.of().formatHex("s3cret".getBytes(StandardCharsets.UTF_8))));
  }
}
