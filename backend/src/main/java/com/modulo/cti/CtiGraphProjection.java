package com.modulo.cti;

import java.util.*;
import org.neo4j.driver.Driver;
import org.neo4j.driver.Session;
import org.neo4j.driver.Value;
import org.neo4j.driver.Values;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Best-effort Neo4j read model of the CTI knowledge graph: {@code (:CtiObject {owner, id})} nodes
 * and typed {@code [:CTI_REL {id, type}]} edges. Postgres stays authoritative; every write here
 * logs and swallows failures, and without a driver every method is a no-op.
 */
@Service
public class CtiGraphProjection {
  private static final Logger logger = LoggerFactory.getLogger(CtiGraphProjection.class);
  private final Optional<Driver> driver;

  public CtiGraphProjection(Optional<Driver> driver) {
    this.driver = driver;
  }

  public boolean isAvailable() {
    return driver.isPresent();
  }

  public void upsertObject(long owner, UUID id, String kind, String name, String tlp, String status) {
    run(
        "MERGE (n:CtiObject {owner: $owner, id: $id}) SET n.kind = $kind, n.name = $name, n.tlp = $tlp,"
            + " n.status = $status",
        Values.parameters(
            "owner", owner, "id", id.toString(), "kind", kind, "name", name, "tlp", tlp, "status", status));
  }

  public void deleteObject(long owner, UUID id) {
    run(
        "MATCH (n:CtiObject {owner: $owner, id: $id}) DETACH DELETE n",
        Values.parameters("owner", owner, "id", id.toString()));
  }

  public void upsertRelationship(long owner, UUID id, UUID source, UUID target, String type) {
    run(
        "MERGE (s:CtiObject {owner: $owner, id: $source}) MERGE (t:CtiObject {owner: $owner, id: $target})"
            + " MERGE (s)-[r:CTI_REL {id: $id}]->(t) SET r.type = $type",
        Values.parameters(
            "owner", owner, "id", id.toString(), "source", source.toString(), "target", target.toString(),
            "type", type));
  }

  public void deleteRelationship(long owner, UUID id) {
    run(
        "MATCH (:CtiObject {owner: $owner})-[r:CTI_REL {id: $id}]->() DELETE r",
        Values.parameters("owner", owner, "id", id.toString()));
  }

  /** Rebuilds the owner's projection from the authoritative rows. */
  public boolean reproject(long owner, List<Map<String, Object>> objects, List<Map<String, Object>> edges) {
    if (driver.isEmpty()) return false;
    try (Session session = driver.get().session()) {
      session.writeTransaction(
          tx -> {
            tx.run("MATCH (n:CtiObject {owner: $owner}) DETACH DELETE n", Values.parameters("owner", owner));
            List<Map<String, Object>> nodes = new ArrayList<>();
            for (var row : objects)
              nodes.add(Map.of(
                  "id", row.get("id").toString(), "kind", row.get("kind"), "name", row.get("name"),
                  "tlp", row.get("tlp"), "status", row.get("status")));
            tx.run(
                "UNWIND $rows AS row MERGE (n:CtiObject {owner: $owner, id: row.id})"
                    + " SET n.kind = row.kind, n.name = row.name, n.tlp = row.tlp, n.status = row.status",
                Values.parameters("owner", owner, "rows", nodes));
            List<Map<String, Object>> rels = new ArrayList<>();
            for (var row : edges)
              rels.add(Map.of(
                  "id", row.get("id").toString(), "source", row.get("sourceId").toString(),
                  "target", row.get("targetId").toString(), "type", row.get("type")));
            tx.run(
                "UNWIND $rows AS row MATCH (s:CtiObject {owner: $owner, id: row.source})"
                    + " MATCH (t:CtiObject {owner: $owner, id: row.target})"
                    + " MERGE (s)-[r:CTI_REL {id: row.id}]->(t) SET r.type = row.type",
                Values.parameters("owner", owner, "rows", rels));
            return null;
          });
      return true;
    } catch (Exception failure) {
      logger.warn("CTI reprojection failed: {}", failure.getMessage());
      return false;
    }
  }

  private void run(String cypher, Value parameters) {
    if (driver.isEmpty()) return;
    try (Session session = driver.get().session()) {
      session.writeTransaction(tx -> {
        tx.run(cypher, parameters);
        return null;
      });
    } catch (Exception failure) {
      logger.warn("CTI graph projection write failed: {}", failure.getMessage());
    }
  }
}
