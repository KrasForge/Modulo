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

/** History diffs, inference rules, notes, sightings and decay, CSV import and ATT&CK. */
@Testcontainers
class CtiAnalysisTest {
  @Container
  static final PostgreSQLContainer<?> database = new PostgreSQLContainer<>(org.testcontainers.utility.DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

  static DriverManagerDataSource source;
  final ObjectMapper json = new ObjectMapper();
  JdbcTemplate jdbc;
  CtiService cti;
  CtiExportService exports;
  CtiCsvImport csv;

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
    csv = new CtiCsvImport(cti, taxonomy);
  }

  ObjectNode attrs(Object... pairs) {
    ObjectNode node = json.createObjectNode();
    for (int i = 0; i < pairs.length; i += 2) node.set((String) pairs[i], json.valueToTree(pairs[i + 1]));
    return node;
  }

  UUID create(String kind, String name, ObjectNode attributes) {
    return (UUID) cti.create(1, new CtiService.ObjectInput(kind, name, null, "amber", null, null, attributes, null, null, null, null), "manual").get("id");
  }

  UUID link(UUID from, UUID to, String type) {
    return (UUID) cti.link(1, new CtiService.RelationshipInput(from, to, type, 70, null, null, null, null), "manual").get("id");
  }

  @SuppressWarnings("unchecked")
  List<Map<String, Object>> rels(UUID id) {
    return (List<Map<String, Object>>) cti.detail(1, id).get("relationships");
  }

  Optional<Map<String, Object>> edge(UUID from, UUID to, String type) {
    return rels(from).stream().filter(r -> type.equals(r.get("type")) && to.equals(r.get("targetId")) && from.equals(r.get("sourceId"))).findFirst();
  }

  static String code(Runnable action) {
    return assertThrows(ResponseStatusException.class, action::run).getReason();
  }

  @Test
  @SuppressWarnings("unchecked")
  void journalRecordsOldAndNewValuesPerField() {
    UUID lead = create("lead", "Lead 153", attrs("priority", "P2", "nextStep", "pivot"));
    cti.update(1, lead, new CtiService.ObjectInput(null, "Lead 153", "closed", "amber", 80, null,
        attrs("priority", "P1", "outcome", "attributed"), null, null, null, 0L), "manual");
    Map<String, Object> change = ((List<Map<String, Object>>) cti.changes(1, null, lead, 5).get("items")).get(0);
    JsonNode detail = (JsonNode) change.get("detail");
    assertEquals(List.of("status", "confidence", "attributes.nextStep", "attributes.outcome", "attributes.priority"),
        CtiService.strings(detail.get("fields")));
    assertEquals("open", detail.at("/changes/status/from").asText());
    assertEquals("closed", detail.at("/changes/status/to").asText());
    assertEquals("P2", detail.at("/changes/attributes.priority/from").asText());
    assertEquals("pivot", detail.at("/changes/attributes.nextStep/from").asText());
    assertTrue(detail.at("/changes/attributes.nextStep/to").isNull());
    assertEquals(80, detail.at("/changes/confidence/to").asInt());
  }

  @Test
  void aliasRotationAndIndicatorRulesDeriveAndRetractEdges() {
    UUID actor = create("actor", "TronzitVeca", attrs());
    UUID apollo = create("identity", null, attrs("identityType", "handle", "value", "apollo1030109"));
    UUID app = create("identity", null, attrs("identityType", "handle", "value", "0xapp123"));
    UUID ed = create("identity", null, attrs("identityType", "handle", "value", "0xed123"));
    link(app, apollo, "alias-of");
    link(ed, app, "alias-of");
    UUID attribution = link(apollo, actor, "attributed-to");
    // Rule 1: every alias inherits the attribution, transitively.
    assertEquals("alias-attribution", edge(ed, actor, "attributed-to").orElseThrow().get("inferredBy"));
    assertEquals(70, edge(app, actor, "attributed-to").orElseThrow().get("confidence"));
    assertEquals(0L, cti.list(1, null, "unattributed-identities", null, null, null, null, 0, 10).get("total"));

    // Rule 2: rotations share attribution and users; Rule 3: indicators follow.
    UUID cdn5 = create("infrastructure", null, attrs("infraKind", "blob-host", "value", "cdn5.example.ink"));
    UUID cdn6 = create("infrastructure", null, attrs("infraKind", "blob-host", "value", "cdn6.example.ink"));
    UUID malware = create("malware", "Overlord", attrs("role", "stealer"));
    link(cdn6, cdn5, "rotation-of");
    link(cdn5, actor, "attributed-to");
    link(malware, cdn5, "uses");
    assertEquals("rotation-inheritance", edge(cdn6, actor, "attributed-to").orElseThrow().get("inferredBy"));
    assertEquals("rotation-inheritance", edge(malware, cdn6, "uses").orElseThrow().get("inferredBy"));
    UUID indicator = create("indicator", null, attrs("indicatorType", "domain", "value", "cdn6.example.ink"));
    link(indicator, cdn6, "based-on");
    assertEquals("indicator-propagation", edge(indicator, actor, "indicates").orElseThrow().get("inferredBy"));

    // Inferred edges cannot be unlinked by hand, and asserting one promotes it to explicit.
    UUID inferred = (UUID) edge(ed, actor, "attributed-to").orElseThrow().get("id");
    assertEquals("CTI_INFERRED_RELATIONSHIP", code(() -> cti.unlink(1, inferred)));
    link(app, actor, "attributed-to");
    assertNull(edge(app, actor, "attributed-to").orElseThrow().get("inferredBy"));

    // Removing the premise retracts what depended only on it.
    cti.unlink(1, attribution);
    assertTrue(edge(ed, actor, "attributed-to").isPresent(), "still derivable through the promoted 0xapp123 edge");
    assertTrue(edge(apollo, actor, "attributed-to").isPresent());
    cti.unlink(1, (UUID) edge(app, actor, "attributed-to").orElseThrow().get("id"));
    assertTrue(edge(ed, actor, "attributed-to").isEmpty());
    assertEquals(3L, cti.list(1, null, "unattributed-identities", null, null, null, null, 0, 10).get("total"));
    Object deleted = jdbc.queryForObject("SELECT count(*) FROM cti_changes WHERE owner_id = 1 AND action = 'retracted'", Long.class);
    assertEquals(2L, deleted, "0xed123 and apollo1030109 lost their derived attribution");
    // Deleting the rotation premise object retracts its derived edges.
    long revision = (long) cti.object(1, cdn5).get("revision");
    cti.delete(1, cdn5, revision);
    assertTrue(edge(cdn6, actor, "attributed-to").isEmpty());
    assertTrue(edge(indicator, actor, "indicates").isEmpty());
  }

  @Test
  @SuppressWarnings("unchecked")
  void notesAndOpinionsAttachToRecordsAndRoundTrip() {
    UUID actor = create("actor", "TronzitVeca", attrs());
    cti.addNote(1, actor, new CtiService.NoteInput("note", "Same build path in both loaders.", null, null, null));
    Map<String, Object> opinion = cti.addNote(1, actor, new CtiService.NoteInput("opinion", "Weak OPSEC", "agree", "green", null));
    assertEquals("CTI_INVALID_OPINION", code(() -> cti.addNote(1, actor, new CtiService.NoteInput("opinion", "x", "maybe", null, null))));
    assertEquals("CTI_NOTE_BODY_REQUIRED", code(() -> cti.addNote(1, actor, new CtiService.NoteInput("note", " ", null, null, null))));
    cti.updateNote(1, (UUID) opinion.get("id"), new CtiService.NoteInput(null, "Weak OPSEC", "strongly-agree", "green", 0L));
    assertEquals("CTI_STALE_REVISION", code(() -> cti.updateNote(1, (UUID) opinion.get("id"), new CtiService.NoteInput(null, "x", "agree", null, 0L))));
    List<Map<String, Object>> notes = (List<Map<String, Object>>) cti.detail(1, actor).get("notes");
    assertEquals(2, notes.size());
    assertEquals("amber", notes.get(1).get("tlp"), "notes default to the record's TLP");

    Map<String, Object> bundle = exports.stix(1, new CtiExportService.Options("amber", false, null));
    String text = exports.canonicalJson(bundle);
    assertTrue(text.contains("\"type\":\"note\"") && text.contains("\"opinion\":\"strongly-agree\""));
    assertFalse(exports.canonicalJson(exports.stix(1, new CtiExportService.Options("green", false, null))).contains("Same build path"),
        "the amber note stays out of a green export (its record is amber too)");
    var imported = exports.importStix(2, json.valueToTree(bundle));
    assertEquals(2, imported.get("notesCreated"));
    assertEquals(0, exports.importStix(2, json.valueToTree(bundle)).get("notesCreated"), "re-import does not duplicate notes");
  }

  @Test
  @SuppressWarnings("unchecked")
  void sightingsAreIdempotentRaiseScoresAndDecayIsQueryable() {
    UUID fresh = create("indicator", null, attrs("indicatorType", "ipv4", "value", "203.0.113.7"));
    UUID old = create("indicator", null, attrs("indicatorType", "ipv4", "value", "198.51.100.1"));
    jdbc.update("UPDATE cti_objects SET created_at = now() - interval '200 days', updated_at = now() - interval '200 days' WHERE id = ?", old);
    assertEquals(50, cti.object(1, fresh).get("score"));
    assertEquals(30, cti.object(1, fresh).get("halfLifeDays"));
    assertTrue((Integer) cti.object(1, old).get("score") < 5, "an IP untouched for 200 days has decayed");
    assertEquals(List.of(old), ((List<Map<String, Object>>) cti.list(1, null, "decayed-indicators", null, null, null, null, 0, 10).get("items"))
        .stream().map(item -> item.get("id")).toList());

    var input = new CtiService.SightingInput("2026-11-10T08:00:00Z", "2026-11-10T09:00:00Z", 3, "honeypot-eu", 80, null, List.of("203.0.113[.]7"));
    assertEquals(true, cti.addSighting(1, fresh, input, "manual").get("recorded"));
    assertEquals(false, cti.addSighting(1, fresh, input, "manual").get("recorded"), "the same report is idempotent");
    jdbc.update("UPDATE cti_sightings SET last_seen = now() - interval '1 hour', first_seen = now() - interval '2 hours'");
    assertEquals(65, cti.object(1, fresh).get("score"), "three recent sightings add 15");
    // A sighting revives a decayed indicator.
    cti.ingest(1, new CtiService.IngestBatch("cron:ids", List.of(), List.of(), null, List.of(new CtiService.IngestSighting(
        json.valueToTree(Map.of("kind", "indicator", "key", "ipv4:198.51.100.1")), null, null, 1, "ids", null, null, null))));
    assertTrue((Integer) cti.object(1, old).get("score") >= 50);
    assertEquals(0L, cti.list(1, null, "decayed-indicators", null, null, null, null, 0, 10).get("total"));
    Map<String, Object> detail = cti.detail(1, fresh);
    List<Map<String, Object>> sightings = (List<Map<String, Object>>) detail.get("sightings");
    assertEquals("203.0.113.7", CtiService.strings((JsonNode) sightings.get(0).get("observed")).get(0));
    assertEquals("CTI_NOT_SIGHTABLE", code(() -> cti.addSighting(1, create("lead", "L", attrs()), input, "manual")));

    String bundle = exports.canonicalJson(exports.stix(1, new CtiExportService.Options("amber", false, null)));
    assertTrue(bundle.contains("\"type\":\"sighting\"") && bundle.contains("\"count\":3") && bundle.contains("\"x_modulo_score\""));
    var imported = exports.importStix(2, json.valueToTree(exports.stix(1, new CtiExportService.Options("amber", false, null))));
    assertEquals(2, imported.get("sightingsRecorded"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void csvImportValidatesEveryRowAndLinksTargets() {
    create("actor", "TronzitVeca", attrs());
    String file = "﻿value,identityType,platform,tlp,labels,rel:attributed-to,rel:alias-of\r\n"
        + "apollo1030109,handle,GitHub,amber,npm;tron,actor:TronzitVeca,\r\n"
        + "\"0xapp123\",handle,\"Git\"\"Hub\",green,,,identity:handle:apollo1030109\n"
        + "bad@,email,,,,,\n"
        + "x,handle,,purple,,,\n"
        + "y,handle,,,,actor:nobody,\n";
    var report = csv.run(1, "identity", file, false, false);
    assertEquals(5, report.get("rows"));
    assertEquals(false, report.get("imported"));
    List<CtiCsvImport.RowError> errors = (List<CtiCsvImport.RowError>) report.get("errors");
    assertEquals(List.of("CTI_INVALID_EMAIL", "CTI_INVALID_TLP", "CTI_UNRESOLVED_REFERENCE"), errors.stream().map(CtiCsvImport.RowError::code).toList());
    assertEquals(List.of(4, 5, 6), errors.stream().map(CtiCsvImport.RowError::row).toList());
    assertEquals(0L, cti.list(1, "identity", null, null, null, null, null, 0, 10).get("total"));

    var imported = csv.run(1, "identity", file, false, true);
    assertEquals(true, imported.get("imported"));
    assertEquals(2, ((Map<String, Object>) imported.get("result")).get("created"));
    var app = (Map<String, Object>) ((List<?>) cti.list(1, "identity", null, "0xapp123", null, null, null, 0, 10).get("items")).get(0);
    assertEquals("Git\"Hub", ((JsonNode) app.get("attributes")).get("platform").asText());
    assertEquals("alias-attribution", edge((UUID) app.get("id"),
        (UUID) ((Map<?, ?>) ((List<?>) cti.list(1, "actor", null, null, null, null, null, 0, 1).get("items")).get(0)).get("id"),
        "attributed-to").orElseThrow().get("inferredBy"), "CSV links feed inference");
    assertEquals(List.of("CTI_CSV_UNKNOWN_COLUMN"),
        ((List<CtiCsvImport.RowError>) csv.run(1, "identity", "value,password\nx,y\n", true, false).get("errors")).stream().map(CtiCsvImport.RowError::code).toList());
    assertEquals("CTI_CSV_UNTERMINATED_QUOTE", code(() -> csv.run(1, "identity", "value\n\"x\n", true, false)));
    assertTrue(csv.template("indicator").startsWith("name,status,tlp,confidence,labels,firstSeen,lastSeen,description,indicatorType,value"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void attackTechniquesHaveNamesTacticsAndUsage() {
    CtiAttackLibrary library = new CtiAttackLibrary();
    assertTrue(library.size() > 500);
    assertEquals("Command and Scripting Interpreter: JavaScript", library.displayName("T1059.007"));
    UUID malware = create("malware", "Overlord", attrs("ttps", List.of("t1059.007")));
    create("actor", "TronzitVeca", attrs("ttps", List.of("T1059.007", "T1195.002")));
    var usage = (Map<String, List<Map<String, Object>>>) cti.attackUsage(1).get("usage");
    assertEquals(2, usage.get("T1059.007").size());
    assertEquals(malware, usage.get("T1059.007").get(0).get("id"));
    String bundle = exports.canonicalJson(exports.stix(1, new CtiExportService.Options("amber", false, null)));
    assertTrue(bundle.contains("\"name\":\"Command and Scripting Interpreter: JavaScript\""));
    assertTrue(bundle.contains("\"phase_name\":\"execution\""));
  }
}
