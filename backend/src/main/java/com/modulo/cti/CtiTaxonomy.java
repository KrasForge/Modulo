package com.modulo.cti;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * The CTI object vocabulary, loaded from the taxonomy shared with the frontend
 * ({@code shared/cti/cti-taxonomy.v1.json}). Every kind has an immutable attribute schema;
 * unknown attributes are rejected rather than stored.
 */
@Component
public class CtiTaxonomy {
  public static final List<String> TLP = List.of("clear", "green", "amber", "amber+strict", "red");
  public static final Set<String> KNOWLEDGE_KINDS =
      Set.of("actor", "identity", "infrastructure", "malware", "indicator", "campaign", "victim");

  public record Attribute(
      String key,
      String type,
      boolean required,
      List<String> options,
      String format,
      boolean observable,
      boolean privateField,
      boolean readOnly) {}

  public record Kind(
      String id,
      String stixType,
      String naturalKey,
      List<String> statuses,
      Map<String, Attribute> attributes,
      boolean privateKind) {
    public boolean knowledge() {
      return KNOWLEDGE_KINDS.contains(id);
    }
  }

  public record RelationshipRule(Set<String> from, Set<String> to) {
    boolean allows(String source, String target) {
      return (from.contains("*") || from.contains(source)) && (to.contains("*") || to.contains(target));
    }
  }

  private final Map<String, Kind> kinds = new LinkedHashMap<>();
  private final Map<String, RelationshipRule> relationships = new LinkedHashMap<>();
  private final String defaultTlp;

  public CtiTaxonomy() {
    JsonNode root;
    try (InputStream in = CtiTaxonomy.class.getResourceAsStream("/cti/cti-taxonomy.v1.json")) {
      if (in == null) throw new IllegalStateException("CTI taxonomy resource missing");
      root = new ObjectMapper().readTree(in);
    } catch (IOException failure) {
      throw new IllegalStateException("CTI taxonomy unreadable", failure);
    }
    if (root.path("version").asInt() != 1) throw new IllegalStateException("Unsupported CTI taxonomy");
    defaultTlp = root.path("defaultTlp").asText("amber");
    root.path("kinds")
        .fields()
        .forEachRemaining(
            entry -> {
              JsonNode kind = entry.getValue();
              Map<String, Attribute> attributes = new LinkedHashMap<>();
              kind.path("attributes")
                  .fields()
                  .forEachRemaining(
                      attribute -> {
                        JsonNode spec = attribute.getValue();
                        List<String> options = new ArrayList<>();
                        spec.path("options").forEach(option -> options.add(option.asText()));
                        attributes.put(
                            attribute.getKey(),
                            new Attribute(
                                attribute.getKey(),
                                spec.path("type").asText(),
                                spec.path("required").asBoolean(false),
                                List.copyOf(options),
                                spec.path("format").asText(null),
                                spec.path("observable").asBoolean(false),
                                spec.path("private").asBoolean(false),
                                spec.path("readOnly").asBoolean(false)));
                      });
              List<String> statuses = new ArrayList<>();
              kind.path("statuses").forEach(status -> statuses.add(status.asText()));
              kinds.put(
                  entry.getKey(),
                  new Kind(
                      entry.getKey(),
                      kind.path("stixType").asText(null),
                      kind.path("naturalKey").asText("name"),
                      List.copyOf(statuses),
                      Collections.unmodifiableMap(attributes),
                      kind.path("private").asBoolean(false)));
            });
    root.path("relationships")
        .fields()
        .forEachRemaining(
            entry -> {
              Set<String> from = new HashSet<>();
              Set<String> to = new HashSet<>();
              entry.getValue().path("from").forEach(value -> from.add(value.asText()));
              entry.getValue().path("to").forEach(value -> to.add(value.asText()));
              relationships.put(entry.getKey(), new RelationshipRule(Set.copyOf(from), Set.copyOf(to)));
            });
  }

  public Kind kind(String id) {
    Kind kind = id == null ? null : kinds.get(id);
    if (kind == null) throw bad("CTI_UNKNOWN_KIND");
    return kind;
  }

  public boolean hasKind(String id) {
    return id != null && kinds.containsKey(id);
  }

  public Collection<Kind> kinds() {
    return kinds.values();
  }

  public Set<String> relationshipTypes() {
    return relationships.keySet();
  }

  public String defaultTlp() {
    return defaultTlp;
  }

  /** Throws unless the typed edge is allowed between these two kinds. */
  public void requireRelationship(String type, String sourceKind, String targetKind) {
    RelationshipRule rule = type == null ? null : relationships.get(type);
    if (rule == null) throw bad("CTI_UNKNOWN_RELATIONSHIP");
    if (!rule.allows(sourceKind, targetKind)) throw bad("CTI_RELATIONSHIP_NOT_ALLOWED");
  }

  public boolean relationshipAllowed(String type, String sourceKind, String targetKind) {
    RelationshipRule rule = type == null ? null : relationships.get(type);
    return rule != null && rule.allows(sourceKind, targetKind);
  }

  public static String tlp(String value) {
    String normalized = value == null ? null : value.trim().toLowerCase(Locale.ROOT).replace("tlp:", "");
    if ("white".equals(normalized)) normalized = "clear";
    if (normalized == null || !TLP.contains(normalized)) throw bad("CTI_INVALID_TLP");
    return normalized;
  }

  public static int tlpRank(String tlp) {
    return TLP.indexOf(tlp);
  }

  public static String stricterTlp(String left, String right) {
    if (left == null) return right;
    if (right == null) return left;
    return tlpRank(left) >= tlpRank(right) ? left : right;
  }

  static ResponseStatusException bad(String code) {
    return new ResponseStatusException(HttpStatus.BAD_REQUEST, code);
  }
}
