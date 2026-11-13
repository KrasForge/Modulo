package com.modulo.cti;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.web.server.ResponseStatusException;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;

@Testcontainers
class CtiServiceTest {
  @Container
  static final PostgreSQLContainer<?> database = new PostgreSQLContainer<>(org.testcontainers.utility.DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

  static DriverManagerDataSource source;
  final ObjectMapper json = new ObjectMapper();
  JdbcTemplate jdbc;
  CtiService cti;
  CtiExportService exports;

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
  }

  ObjectNode attrs(Object... pairs) {
    ObjectNode node = json.createObjectNode();
    for (int i = 0; i < pairs.length; i += 2) node.set((String) pairs[i], json.valueToTree(pairs[i + 1]));
    return node;
  }

  UUID create(long owner, String kind, String name, String tlp, ObjectNode attributes) {
    return (UUID) cti.create(owner, new CtiService.ObjectInput(kind, name, null, tlp, null, null, attributes, null, null, null, null), "manual").get("id");
  }

  void link(long owner, UUID from, UUID to, String type) {
    cti.link(owner, new CtiService.RelationshipInput(from, to, type, null, null, null, null, null), "manual");
  }

  static String code(Runnable action) {
    return assertThrows(ResponseStatusException.class, action::run).getReason();
  }

  @Test
  void refangsValidatesAndDeduplicatesObservables() {
    UUID c2 = create(1, "infrastructure", null, "amber", attrs("infraKind", "domain", "value", "evil[.]Example[.]ink"));
    Map<String, Object> object = cti.object(1, c2);
    assertEquals("evil.example.ink", object.get("name"));
    assertEquals("domain:evil.example.ink", object.get("naturalKey"));
    assertEquals("CTI_DUPLICATE_OBJECT", code(() -> create(1, "infrastructure", null, "amber", attrs("infraKind", "domain", "value", "EVIL.example.ink"))));
    assertEquals("CTI_INVALID_DOMAIN", code(() -> create(1, "infrastructure", null, "amber", attrs("infraKind", "domain", "value", "not a domain"))));
    assertEquals("CTI_UNKNOWN_ATTRIBUTE", code(() -> create(1, "actor", "X", "amber", attrs("password", "nope"))));
    assertEquals("CTI_INVALID_ATTACK_TECHNIQUE", code(() -> create(1, "actor", "X", "amber", attrs("ttps", List.of("execution")))));
    assertEquals("CTI_INVALID_HASH", code(() -> create(1, "malware", "m", "amber", attrs("sha256", "abc"))));
    // Another owner can hold the same observable; reads are owner-scoped.
    create(2, "infrastructure", null, "amber", attrs("infraKind", "domain", "value", "evil.example.ink"));
    assertEquals("CTI_NOT_FOUND", code(() -> cti.object(2, c2)));
    assertEquals(1L, cti.list(2, "infrastructure", null, null, null, null, null, 0, 50).get("total"));
  }

  @Test
  void ingestIsIdempotentWidensWindowsAndNeverDowngradesTlp() {
    var first = new CtiService.IngestBatch("watch:test", List.of(
        new CtiService.IngestObject("a", "actor", "TronzitVeca", null, "red", 60, null, attrs("aliases", List.of("Tr1030109")), null, "2026-01-01", "2026-02-01"),
        new CtiService.IngestObject("i", "identity", null, null, "amber", null, null, attrs("identityType", "handle", "value", "apollo1030109", "platform", "GitHub"), null, null, null)),
        List.of(new CtiService.IngestRelationship(json.getNodeFactory().textNode("i"), json.getNodeFactory().textNode("a"), "attributed-to", 80, null, null, null, null)),
        null);
    var result = cti.ingest(1, first);
    assertEquals(2, result.get("created"));
    assertEquals(1, result.get("relationshipsCreated"));
    var again = cti.ingest(1, first);
    assertEquals(0, again.get("created"));
    assertEquals(2, again.get("unchanged"));
    assertEquals(0, again.get("relationshipsCreated"));

    var update = cti.ingest(1, new CtiService.IngestBatch("watch:test", List.of(
        new CtiService.IngestObject(null, "actor", "tronzitveca", "active", "green", null, null, attrs("aliases", List.of("0xapp123", "TR1030109")), null, "2025-12-01", "2026-03-01")),
        null, null));
    assertEquals(1, update.get("updated"));
    UUID actor = (UUID) ((Map<?, ?>) ((List<?>) result.get("results")).get(0)).get("id");
    var stored = cti.object(1, actor);
    assertEquals("red", stored.get("tlp"), "ingest must never downgrade TLP");
    assertEquals("TronzitVeca", stored.get("name"));
    assertEquals(List.of("Tr1030109", "0xapp123"), CtiService.strings(((JsonNode) stored.get("attributes")).get("aliases")));
    assertEquals("2025-12-01T00:00:00Z", stored.get("firstSeen"));
    assertEquals("2026-03-01T00:00:00Z", stored.get("lastSeen"));
    assertEquals(60, stored.get("confidence"));

    // Natural-key references resolve existing objects; unknown ones fail the whole batch.
    var linked = cti.ingest(1, new CtiService.IngestBatch(null, List.of(
        new CtiService.IngestObject("w", "identity", null, null, null, null, null, attrs("identityType", "wallet", "value", "TXYZwallet1"), null, null, null)),
        List.of(new CtiService.IngestRelationship(json.getNodeFactory().textNode("w"), json.valueToTree(Map.of("kind", "actor", "key", "TronzitVeca")), "attributed-to", null, null, null, null, null)), null));
    assertEquals(1, linked.get("relationshipsCreated"));
    assertEquals("CTI_UNRESOLVED_REFERENCE", code(() -> cti.ingest(1, new CtiService.IngestBatch(null, List.of(),
        List.of(new CtiService.IngestRelationship(json.valueToTree(Map.of("kind", "actor", "key", "nobody")), json.getNodeFactory().textNode("w"), "uses", null, null, null, null, null)), null))));
    assertEquals(List.of("updated", "created"), ((List<?>) cti.changes(1, null, actor, 50).get("items")).stream().map(c -> ((Map<?, ?>) c).get("action")).toList());
  }

  @Test
  void relationshipRulesAliasAttributionAndGraphNeighbourhood() {
    UUID actor = create(1, "actor", "TronzitVeca", "amber", attrs());
    UUID a = create(1, "identity", null, "amber", attrs("identityType", "handle", "value", "apollo1030109"));
    UUID b = create(1, "identity", null, "amber", attrs("identityType", "handle", "value", "0xed123"));
    UUID loner = create(1, "identity", null, "amber", attrs("identityType", "email", "value", "x@example.org"));
    UUID infra = create(1, "infrastructure", null, "amber", attrs("infraKind", "c2", "value", "203.0.113.7"));
    cti.update(1, infra, new CtiService.ObjectInput(null, null, "live", "amber", null, null, attrs("infraKind", "c2", "value", "203.0.113.7"), null, null, null, 0L), "manual");
    assertEquals("CTI_RELATIONSHIP_NOT_ALLOWED", code(() -> link(1, infra, actor, "uses")));
    assertEquals("CTI_UNKNOWN_RELATIONSHIP", code(() -> link(1, a, actor, "owns")));
    assertEquals("CTI_SELF_RELATIONSHIP", code(() -> link(1, a, a, "alias-of")));
    link(1, a, actor, "attributed-to");
    link(1, b, a, "alias-of");
    link(1, actor, infra, "uses");

    var unattributed = cti.list(1, null, "unattributed-identities", null, null, null, null, 0, 50);
    assertEquals(List.of(loner), ((List<?>) unattributed.get("items")).stream().map(item -> ((Map<?, ?>) item).get("id")).toList());
    assertEquals(1L, cti.list(1, null, "live-c2", null, null, null, null, 0, 50).get("total"));

    // A lead that concerns everything must not bridge unrelated clusters in the knowledge graph.
    UUID lead = create(1, "lead", "Lead 153", "amber", attrs("number", "153", "priority", "P1"));
    link(1, lead, loner, "concerns");
    link(1, lead, infra, "concerns");
    var graph = cti.graph(1, b, 3, 100, false);
    Set<Object> nodes = new HashSet<>(((List<?>) graph.get("nodes")).stream().map(n -> ((Map<?, ?>) n).get("id")).toList());
    assertEquals(Set.of(b, a, actor, infra), nodes);
    assertEquals(4, ((List<?>) graph.get("edges")).size(), "three explicit edges plus the inferred 0xed123 attribution");
    var leadGraph = cti.graph(1, lead, 1, 100, true);
    assertEquals(3, ((List<?>) leadGraph.get("nodes")).size());
    var detail = cti.detail(1, lead);
    assertEquals(2, ((List<?>) detail.get("relationships")).size());
    assertEquals(1L, cti.list(1, null, "open-leads", null, null, null, null, 0, 50).get("total"));
    assertEquals(0L, cti.list(1, null, "stale-leads", null, null, null, null, 0, 50).get("total"));
    jdbc.update("UPDATE cti_objects SET updated_at = now() - interval '30 days' WHERE id = ?", lead);
    assertEquals(1L, cti.list(1, null, "stale-leads", null, null, null, null, 0, 50).get("total"));
    var summary = cti.summary(1);
    assertEquals(3L, ((Map<?, ?>) summary.get("counts")).get("identity"));
    assertEquals(1L, ((Map<?, ?>) ((Map<?, ?>) summary.get("views")).get("unattributed-identities")).get("total"));
  }

  @Test
  void updatesUseRevisionsAndMergeFoldsDuplicates() {
    UUID keep = create(1, "actor", "TronzitVeca", "amber", attrs("aliases", List.of("TV")));
    UUID dup = create(1, "actor", "PolinRider operator", "red", attrs("ttps", List.of("T1059.007")));
    UUID infra = create(1, "infrastructure", null, "amber", attrs("infraKind", "dead-drop", "value", "https://gitlab.example/x"));
    link(1, dup, infra, "uses");
    link(1, keep, infra, "uses");
    assertEquals("CTI_STALE_REVISION", code(() -> cti.update(1, keep, new CtiService.ObjectInput(null, "TronzitVeca", null, null, null, null, attrs(), null, null, null, 5L), "manual")));
    var merged = cti.merge(1, dup, keep);
    JsonNode attributes = (JsonNode) merged.get("attributes");
    assertEquals(List.of("TV", "PolinRider operator"), CtiService.strings(attributes.get("aliases")));
    assertEquals(List.of("T1059.007"), CtiService.strings(attributes.get("ttps")));
    assertEquals("red", merged.get("tlp"));
    assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM cti_relationships WHERE owner_id = 1", Integer.class));
    assertEquals("CTI_NOT_FOUND", code(() -> cti.object(1, dup)));
  }

  @Test
  void watchRunsRecordFindingsAndLinkThem() {
    var batch = new CtiService.IngestBatch("cron:ct-watch", List.of(
        new CtiService.IngestObject("d", "infrastructure", null, "live", null, null, null, attrs("infraKind", "blob-host", "value", "cdn1.example.ink"), null, null, null)),
        null, new CtiService.WatchRun("certificate-transparency", "*.example.ink", "1 new host", null));
    UUID watch = (UUID) cti.ingest(1, batch).get("watch");
    var stored = cti.detail(1, watch);
    assertEquals(1, ((JsonNode) stored.get("attributes")).get("findings").asInt());
    assertEquals("1 new host", ((JsonNode) stored.get("attributes")).get("lastResult").asText());
    assertEquals(1, ((List<?>) stored.get("relationships")).size());
    cti.ingest(1, batch);
    assertEquals(1, ((JsonNode) cti.object(1, watch).get("attributes")).get("findings").asInt());
    assertEquals(0L, cti.list(1, null, "unhealthy-watches", null, null, null, null, 0, 50).get("total"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void stixExportAppliesTlpCeilingRedactsVictimsAndRoundTrips() {
    UUID actor = create(1, "actor", "TronzitVeca", "green", attrs("aliases", List.of("Tr1030109"), "ttps", List.of("T1195.002")));
    UUID wallet = create(1, "identity", null, "green", attrs("identityType", "wallet", "value", "TXYZwallet1", "chain", "tron"));
    UUID secret = create(1, "infrastructure", null, "red", attrs("infraKind", "c2", "value", "198.51.100.9"));
    UUID ind = create(1, "indicator", null, "clear", attrs("indicatorType", "domain", "value", "evil.example.ink"));
    UUID victim = create(1, "victim", "Alice Example", "green", attrs("exposureType", "wallet-drain", "contactChannel", "alice@example.org"));
    UUID malware = create(1, "malware", "Overlord", "green", attrs("role", "stealer", "sha256", "a".repeat(64)));
    link(1, wallet, actor, "attributed-to");
    link(1, actor, secret, "uses");
    link(1, ind, actor, "indicates");
    link(1, actor, victim, "targets");
    link(1, actor, malware, "uses");

    Map<String, Object> bundle = exports.stix(1, new CtiExportService.Options("green", false, null));
    String text = exports.canonicalJson(bundle);
    assertFalse(text.contains("198.51.100.9"), "red objects stay out of a green export");
    assertFalse(text.contains("Alice"), "victims are excluded unless requested");
    List<Map<String, Object>> objects = (List<Map<String, Object>>) bundle.get("objects");
    Set<String> types = new HashSet<>();
    objects.forEach(o -> types.add((String) o.get("type")));
    assertTrue(types.containsAll(Set.of("threat-actor", "cryptocurrency-wallet", "indicator", "malware", "file", "attack-pattern", "relationship", "marking-definition")));
    var indicator = objects.stream().filter(o -> "indicator".equals(o.get("type"))).findFirst().orElseThrow();
    assertEquals("[domain-name:value = 'evil.example.ink']", indicator.get("pattern"));
    assertEquals(List.of(CtiExportService.TLP_MARKINGS.get("clear")), indicator.get("object_marking_refs"));
    assertEquals(bundle.get("id"), exports.stix(1, new CtiExportService.Options("green", false, null)).get("id"), "bundle ids are deterministic");

    String withVictims = exports.canonicalJson(exports.stix(1, new CtiExportService.Options("green", true, null)));
    assertTrue(withVictims.contains("Redacted victim"));
    assertFalse(withVictims.contains("Alice"));
    assertFalse(withVictims.contains("alice@example.org"), "private contact channels are never exported");

    Map<String, Object> misp = exports.misp(1, new CtiExportService.Options("green", true, null), "Share");
    String mispText = exports.canonicalJson(misp);
    assertTrue(mispText.contains("\"type\":\"domain\""));
    assertTrue(mispText.contains("misp-galaxy:threat-actor=\\\"TronzitVeca\\\""));
    assertFalse(mispText.contains("Alice"));

    var imported = exports.importStix(2, json.valueToTree(bundle));
    assertEquals(0, imported.get("unchanged"));
    assertEquals(4L, cti.list(2, null, null, null, null, null, null, 0, 50).get("total"));
    var actor2 = (Map<String, Object>) ((List<?>) cti.list(2, "actor", null, null, null, null, null, 0, 50).get("items")).get(0);
    assertEquals(List.of("T1195.002"), CtiService.strings(((JsonNode) actor2.get("attributes")).get("ttps")));
    assertEquals("green", actor2.get("tlp"));
    assertEquals(3L, jdbc.queryForObject("SELECT count(*) FROM cti_relationships WHERE owner_id = 2", Long.class));
    var reimport = exports.importStix(2, json.valueToTree(bundle));
    assertEquals(4, reimport.get("unchanged"));
  }

  @Test
  void disclosureCapsuleIsScopedAndStamped() {
    UUID actor = create(1, "actor", "TronzitVeca", "amber", attrs());
    UUID infra = create(1, "infrastructure", null, "amber", attrs("infraKind", "blob-host", "value", "cdn.example.ink"));
    UUID other = create(1, "actor", "Unrelated", "clear", attrs());
    UUID victim = create(1, "victim", "Bob", "amber", attrs());
    link(1, actor, infra, "uses");
    link(1, actor, victim, "targets");
    UUID disclosure = create(1, "disclosure", "SEAL report", "amber", attrs("recipient", "SEAL 911", "tlpCeiling", "amber", "capsuleSha256", "forged"));
    assertEquals("CTI_DISCLOSURE_EMPTY", code(() -> exports.capsule(1, disclosure)));
    link(1, disclosure, actor, "concerns");
    var capsule = exports.capsule(1, disclosure);
    String text = exports.canonicalJson(capsule.bundle());
    assertTrue(text.contains("cdn.example.ink"));
    assertFalse(text.contains("Unrelated"));
    assertFalse(text.contains("Bob"));
    assertTrue(text.contains("\"type\":\"report\""));
    assertEquals(CtiExportService.sha256(text), capsule.sha256());
    assertEquals(capsule.sha256(), ((JsonNode) cti.object(1, disclosure).get("attributes")).get("capsuleSha256").asText());
    assertNotNull(other);
  }
}
