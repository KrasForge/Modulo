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
  static final Map<String, String> VIEWS =
      Map.of(
          "live-c2",
          "o.kind = 'infrastructure' AND o.status = 'live' AND o.attributes->>'infraKind' IN ('c2','blob-host','dead-drop')",
          "unattributed-identities",
          "o.kind = 'identity' AND NOT EXISTS (WITH RECURSIVE alias_walk(id, depth) AS ("
              + " SELECT o.id, 0 UNION SELECT CASE WHEN ar.source_id = aw.id THEN ar.target_id ELSE ar.source_id END,"
              + " aw.depth + 1 FROM alias_walk aw JOIN cti_relationships ar ON ar.owner_id = o.owner_id"
              + " AND ar.type = 'alias-of' AND (ar.source_id = aw.id OR ar.target_id = aw.id) WHERE aw.depth < 6)"
              + " SELECT 1 FROM alias_walk aw JOIN cti_relationships ax ON ax.owner_id = o.owner_id"
              + " AND ((ax.source_id = aw.id AND ax.type IN ('attributed-to','part-of'))"
              + " OR (ax.target_id = aw.id AND ax.type IN ('controls','uses'))))",
          "open-leads",
          "o.kind = 'lead' AND o.status <> 'closed'",
          "stale-leads",
          "o.kind = 'lead' AND o.status <> 'closed' AND o.updated_at < now() - interval '14 days'",
          "expiring-indicators",
          "o.kind = 'indicator' AND o.status = 'active' AND o.attributes->>'validUntil' IS NOT NULL"
              + " AND (o.attributes->>'validUntil')::date <= current_date + 14",
          "unhealthy-watches",
          "o.kind = 'watch' AND (o.status = 'failing' OR (o.status = 'active' AND (o.attributes->>'lastRunAt' IS NULL"
              + " OR (o.attributes->>'lastRunAt')::timestamptz < now() - interval '2 days')))",
          "unnotified-victims",
          "o.kind = 'victim' AND coalesce(o.attributes->>'notified', 'false') <> 'true'");

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

  public record IngestBatch(
      String source, List<IngestObject> objects, List<IngestRelationship> relationships, WatchRun watch) {}

  public record Merge(UUID into) {}

  /** A validated object write, with flags for the fields the caller actually supplied. */
  record Candidate(
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
          List<String> changed = diff(existing, c);
          write(owner, id, c);
          change(owner, id, kind, c.name(), "updated", Map.of("fields", changed), source(source));
          after.add(project(owner, id, c));
        });
    after.forEach(Runnable::run);
    return object(owner, id);
  }

  public void delete(long owner, UUID id, long revision) {
    tx.executeWithoutResult(
        status -> {
          Map<String, Object> existing = lock(owner, id);
          if (((Number) existing.get("revision")).longValue() != revision)
            throw new ResponseStatusException(HttpStatus.CONFLICT, "CTI_STALE_REVISION");
          jdbc.update("DELETE FROM cti_objects WHERE owner_id = ? AND id = ?", owner, id);
          change(owner, id, (String) existing.get("kind"), (String) existing.get("name"), "deleted", Map.of(), "manual");
        });
    graph.deleteObject(owner, id);
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
                  + " WHERE owner_id = ? AND (source_id = ? OR target_id = ?)"
                  + " AND NOT ((source_id = ? AND target_id = ?) OR (source_id = ? AND target_id = ?))"
                  + " ON CONFLICT (owner_id, source_id, target_id, type) DO NOTHING",
              sourceId, targetId, sourceId, targetId, owner, sourceId, sourceId, sourceId, targetId, targetId, sourceId);
          jdbc.update("DELETE FROM cti_objects WHERE owner_id = ? AND id = ?", owner, sourceId);
          change(owner, targetId, kind.id(), (String) into.get("name"), "merged",
              Map.of("mergedId", sourceId.toString(), "mergedName", from.get("name")), "manual");
          change(owner, sourceId, kind.id(), (String) from.get("name"), "deleted",
              Map.of("mergedInto", targetId.toString()), "manual");
        });
    reproject(owner);
    return object(owner, targetId);
  }

  // ------------------------------------------------------------------ relationships

  public Map<String, Object> link(long owner, RelationshipInput input, String source) {
    List<Runnable> after = new ArrayList<>();
    Map<String, Object> result =
        tx.execute(status -> upsertRelationship(owner, input, source(source), after));
    after.forEach(Runnable::run);
    return result;
  }

  public void unlink(long owner, UUID id) {
    tx.executeWithoutResult(
        status -> {
          var rows = jdbc.queryForList(
              "DELETE FROM cti_relationships r USING cti_objects o WHERE r.owner_id = ? AND r.id = ?"
                  + " AND o.owner_id = r.owner_id AND o.id = r.source_id RETURNING r.type, r.target_id, o.id AS oid, o.kind, o.name",
              owner, id);
          if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
          var row = rows.get(0);
          change(owner, (UUID) row.get("oid"), (String) row.get("kind"), (String) row.get("name"), "unlinked",
              Map.of("type", row.get("type"), "targetId", row.get("target_id").toString()), "manual");
        });
    graph.deleteRelationship(owner, id);
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
    var row = jdbc.queryForMap(
        "INSERT INTO cti_relationships (owner_id, id, source_id, target_id, type, confidence, description, tlp,"
            + " first_seen, last_seen, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            + " ON CONFLICT (owner_id, source_id, target_id, type) DO UPDATE SET"
            + " confidence = coalesce(EXCLUDED.confidence, cti_relationships.confidence),"
            + " description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE cti_relationships.description END,"
            + " first_seen = least(cti_relationships.first_seen, EXCLUDED.first_seen),"
            + " last_seen = greatest(cti_relationships.last_seen, EXCLUDED.last_seen), updated_at = now()"
            + " RETURNING id, (xmax = 0) AS inserted",
        owner, UUID.randomUUID(), input.sourceId(), input.targetId(), input.type(), confidence, description, tlp,
        ts(first), ts(last), source);
    UUID id = (UUID) row.get("id");
    boolean inserted = Boolean.TRUE.equals(row.get("inserted"));
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
    List<IngestObject> objects = batch.objects() == null ? List.of() : batch.objects();
    List<IngestRelationship> relationships = batch.relationships() == null ? List.of() : batch.relationships();
    if (objects.size() > MAX_BATCH_OBJECTS || relationships.size() > MAX_BATCH_RELATIONSHIPS)
      throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "CTI_BATCH_TOO_LARGE");
    if (objects.isEmpty() && relationships.isEmpty() && batch.watch() == null) throw bad("CTI_EMPTY_BATCH");
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
              Map<String, Object> out = new LinkedHashMap<>();
              out.put("created", counts[0]);
              out.put("updated", counts[1]);
              out.put("unchanged", counts[2]);
              out.put("relationshipsCreated", linked);
              out.put("results", results);
              if (batch.watch() != null) out.put("watch", recordWatch(owner, batch.watch(), counts[0], touched, source, after));
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
    List<String> changed = diff(existing, merged);
    if (changed.isEmpty()) return new LinkedHashMap<>(Map.of("id", id, "kind", c.kind().id(), "action", "unchanged"));
    write(owner, id, merged);
    change(owner, id, c.kind().id(), merged.name(), "updated", Map.of("fields", changed), source);
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
    var rows = jdbc.queryForList("SELECT " + COLUMNS + " FROM cti_objects WHERE owner_id = ? AND id = ?", owner, id);
    if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CTI_NOT_FOUND");
    return row(rows.get(0));
  }

  /** The object plus every relationship, with the far endpoint summarized, and its history. */
  public Map<String, Object> detail(long owner, UUID id) {
    Map<String, Object> out = object(owner, id);
    List<Map<String, Object>> relationships = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT r.id, r.type, r.source_id, r.target_id, r.confidence, r.description, r.tlp, r.first_seen, r.last_seen,"
            + " r.source, r.created_at, o.id AS other_id, o.kind AS other_kind, o.name AS other_name,"
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
      rel.put("other", Map.of("id", row.get("other_id"), "kind", row.get("other_kind"), "name", row.get("other_name"),
          "status", row.get("other_status"), "tlp", row.get("other_tlp")));
      relationships.add(rel);
    }
    out.put("relationships", relationships);
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
    long total = jdbc.queryForObject("SELECT count(*) FROM cti_objects o" + where, Long.class, args.toArray());
    String order = view != null && view.endsWith("leads")
        ? " ORDER BY coalesce(o.attributes->>'priority', 'P9'), o.updated_at DESC, o.id"
        : " ORDER BY o.updated_at DESC, o.id";
    List<Object> pageArgs = new ArrayList<>(args);
    pageArgs.add(limit);
    pageArgs.add((long) page * limit);
    List<Map<String, Object>> items = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT " + columns("o")
            + ", (SELECT count(*) FROM cti_relationships r WHERE r.owner_id = o.owner_id AND (r.source_id = o.id OR r.target_id = o.id)) AS degree"
            + " FROM cti_objects o" + where + order + " LIMIT ? OFFSET ?",
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
        "SELECT id, source_id AS \"sourceId\", target_id AS \"targetId\", type, confidence FROM cti_relationships"
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
    for (String view : List.of("live-c2", "open-leads", "stale-leads", "unattributed-identities", "expiring-indicators", "unhealthy-watches", "unnotified-victims"))
      views.put(view, list(owner, null, view, null, null, null, null, 0, 10));
    out.put("views", views);
    out.put("recentChanges", changes(owner, Instant.now().minusSeconds(7 * 86400).toString(), null, 25));
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
    for (var row : jdbc.queryForList("SELECT " + COLUMNS + " FROM cti_objects WHERE owner_id = ? ORDER BY created_at, id LIMIT ?",
        owner, MAX_OBJECTS_PER_OWNER)) out.add(row(row));
    return out;
  }

  List<Map<String, Object>> allRelationships(long owner) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (var row : jdbc.queryForList(
        "SELECT id, source_id, target_id, type, confidence, description, tlp, first_seen, last_seen, created_at, updated_at"
            + " FROM cti_relationships WHERE owner_id = ? ORDER BY created_at, id", owner)) {
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

  private List<String> diff(Map<String, Object> existing, Candidate c) {
    List<String> changed = new ArrayList<>();
    if (!Objects.equals(existing.get("name"), c.name())) changed.add("name");
    if (!Objects.equals(existing.get("status"), c.status())) changed.add("status");
    if (!Objects.equals(existing.get("tlp"), c.tlp())) changed.add("tlp");
    if (!Objects.equals(existing.get("confidence"), c.confidence())) changed.add("confidence");
    if (!Objects.equals(existing.get("description"), c.description())) changed.add("description");
    if (!Objects.equals(existing.get("attributes"), c.attributes())) changed.add("attributes");
    if (!Objects.equals(strings((JsonNode) existing.get("labels")), c.labels())) changed.add("labels");
    if (!Objects.equals(existing.get("firstSeen"), c.firstSeen() == null ? null : c.firstSeen().toString())) changed.add("firstSeen");
    if (!Objects.equals(existing.get("lastSeen"), c.lastSeen() == null ? null : c.lastSeen().toString())) changed.add("lastSeen");
    return changed;
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
