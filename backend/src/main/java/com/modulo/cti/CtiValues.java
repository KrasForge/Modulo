package com.modulo.cti;

import static com.modulo.cti.CtiTaxonomy.bad;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.time.*;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Pattern;

/** Pure value handling for CTI records: refanging, observable checks, attributes and keys. */
public final class CtiValues {
  private CtiValues() {}

  static final Pattern DOMAIN =
      Pattern.compile("^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\\.)+[a-z0-9-]{2,63}$");
  static final Pattern IPV4 =
      Pattern.compile("^(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$");
  static final Pattern IPV6 = Pattern.compile("^[0-9a-f:.]{2,45}$");
  static final Pattern URL = Pattern.compile("^[a-z][a-z0-9+.-]*://\\S+$", Pattern.CASE_INSENSITIVE);
  static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
  static final Pattern ATTACK = Pattern.compile("^T\\d{4}(?:\\.\\d{3})?$");
  static final Pattern LABEL = Pattern.compile("^[a-z0-9][a-z0-9:._/+-]{0,63}$");
  static final Map<String, Integer> HASH_LENGTH = Map.of("sha256", 64, "sha1", 40, "md5", 32);

  /** Undo the common defanging conventions used when sharing indicators in prose. */
  public static String refang(String value) {
    if (value == null) return null;
    String out = value.trim();
    out = out.replaceAll("(?i)\\[\\s*(?:\\.|dot)\\s*]|\\(\\s*(?:\\.|dot)\\s*\\)|\\{\\s*(?:\\.|dot)\\s*}", ".");
    out = out.replaceAll("(?i)\\[\\s*(?:@|at)\\s*]|\\(\\s*(?:@|at)\\s*\\)", "@");
    out = out.replace("[:]", ":").replace("[://]", "://").replace("[/]", "/");
    out = out.replaceAll("(?i)^hxxp(s?)", "http$1").replaceAll("(?i)^fxp", "ftp");
    return out;
  }

  /** Normalizes and validates an observable value for the given type (indicator, infra or identity). */
  public static String observable(String type, String raw) {
    String value = refang(raw);
    if (value == null || value.isBlank()) throw bad("CTI_VALUE_REQUIRED");
    if (value.length() > 2048) throw bad("CTI_VALUE_TOO_LONG");
    switch (type == null ? "" : type) {
      case "domain":
        value = value.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        if (!DOMAIN.matcher(value).matches()) throw bad("CTI_INVALID_DOMAIN");
        return value;
      case "ipv4":
        if (!IPV4.matcher(value).matches()) throw bad("CTI_INVALID_IPV4");
        return value;
      case "ipv6":
        value = value.toLowerCase(Locale.ROOT);
        if (!IPV6.matcher(value).matches() || !value.contains(":")) throw bad("CTI_INVALID_IPV6");
        return value;
      case "ip":
        if (IPV4.matcher(value).matches()) return value;
        return observable("ipv6", value);
      case "url":
        if (!URL.matcher(value).matches()) throw bad("CTI_INVALID_URL");
        return value;
      case "email":
        value = value.toLowerCase(Locale.ROOT);
        if (!EMAIL.matcher(value).matches()) throw bad("CTI_INVALID_EMAIL");
        return value;
      case "sha256":
      case "sha1":
      case "md5":
        value = value.toLowerCase(Locale.ROOT);
        if (!value.matches("^[0-9a-f]{" + HASH_LENGTH.get(type) + "}$")) throw bad("CTI_INVALID_HASH");
        return value;
      default:
        return value;
    }
  }

  /** Infers an observable family from a free-form value (used for C2 and similar kinds). */
  public static String inferType(String value) {
    if (value == null) return "other";
    String v = value.toLowerCase(Locale.ROOT);
    if (IPV4.matcher(v).matches()) return "ipv4";
    if (v.contains(":") && IPV6.matcher(v).matches()) return "ipv6";
    if (URL.matcher(v).matches()) return "url";
    if (EMAIL.matcher(v).matches()) return "email";
    if (v.matches("^[0-9a-f]{64}$")) return "sha256";
    if (DOMAIN.matcher(v).matches()) return "domain";
    return "other";
  }

  /** Type used to validate the {@code value} attribute of a kind. */
  static String valueType(String kind, ObjectNode attributes) {
    switch (kind) {
      case "indicator":
        return attributes.path("indicatorType").asText("");
      case "infrastructure":
        String infra = attributes.path("infraKind").asText("");
        return Set.of("domain", "ip", "url").contains(infra) ? infra : "";
      case "identity":
        return "email".equals(attributes.path("identityType").asText("")) ? "email" : "";
      default:
        return "";
    }
  }

  /**
   * Validates attributes against the kind's schema and returns the cleaned object. Read-only
   * attributes are kept from {@code existing} unless {@code internal} writes are allowed.
   */
  public static ObjectNode attributes(
      CtiTaxonomy.Kind kind, JsonNode input, JsonNode existing, boolean internal) {
    ObjectNode out = JsonNodeFactory.instance.objectNode();
    if (input != null && !input.isNull() && !input.isObject()) throw bad("CTI_INVALID_ATTRIBUTES");
    if (input != null && input.isObject()) {
      var fields = input.fields();
      while (fields.hasNext()) {
        var field = fields.next();
        CtiTaxonomy.Attribute spec = kind.attributes().get(field.getKey());
        if (spec == null) throw bad("CTI_UNKNOWN_ATTRIBUTE");
        if (spec.readOnly() && !internal) continue;
        JsonNode value = attribute(spec, field.getValue());
        if (value != null) out.set(field.getKey(), value);
      }
    }
    if (existing != null && existing.isObject()) {
      for (CtiTaxonomy.Attribute spec : kind.attributes().values())
        if (spec.readOnly() && !out.has(spec.key()) && existing.has(spec.key()))
          out.set(spec.key(), existing.get(spec.key()));
    }
    if (out.has("value")) {
      String type = valueType(kind.id(), out);
      out.put("value", observable(type, out.get("value").asText()));
    }
    for (CtiTaxonomy.Attribute spec : kind.attributes().values())
      if (spec.required() && (!out.has(spec.key()) || out.get(spec.key()).asText().isBlank()))
        throw bad("CTI_ATTRIBUTE_REQUIRED");
    if (out.toString().length() > 65536) throw bad("CTI_ATTRIBUTES_TOO_LARGE");
    return out;
  }

  private static JsonNode attribute(CtiTaxonomy.Attribute spec, JsonNode value) {
    if (value == null || value.isNull() || (value.isTextual() && value.asText().isBlank())) return null;
    JsonNodeFactory nodes = JsonNodeFactory.instance;
    switch (spec.type()) {
      case "text":
        {
          if (!value.isTextual() && !value.isNumber()) throw bad("CTI_INVALID_ATTRIBUTE");
          String text = value.asText().trim();
          if (text.length() > 4096) throw bad("CTI_ATTRIBUTE_TOO_LONG");
          if ("sha256".equals(spec.format())) text = observable("sha256", text);
          return nodes.textNode(text);
        }
      case "url":
        {
          String text = refang(value.asText());
          if (!text.matches("(?i)^https?://\\S+$") || text.length() > 2048)
            throw bad("CTI_INVALID_URL");
          return nodes.textNode(text);
        }
      case "select":
        if (!spec.options().contains(value.asText())) throw bad("CTI_INVALID_OPTION");
        return nodes.textNode(value.asText());
      case "boolean":
        if (!value.isBoolean()) throw bad("CTI_INVALID_ATTRIBUTE");
        return value;
      case "number":
        if (!value.isNumber() || !Double.isFinite(value.asDouble())) throw bad("CTI_INVALID_ATTRIBUTE");
        return value;
      case "date":
        try {
          return nodes.textNode(LocalDate.parse(value.asText().substring(0, Math.min(10, value.asText().length()))).toString());
        } catch (DateTimeParseException failure) {
          throw bad("CTI_INVALID_DATE");
        }
      case "datetime":
        return nodes.textNode(instant(value.asText()).toString());
      case "list":
        {
          ArrayNode list = nodes.arrayNode();
          Set<String> seen = new LinkedHashSet<>();
          List<JsonNode> items = new ArrayList<>();
          if (value.isArray()) value.forEach(items::add);
          else if (value.isTextual()) for (String part : value.asText().split(",")) items.add(nodes.textNode(part));
          else throw bad("CTI_INVALID_ATTRIBUTE");
          for (JsonNode item : items) {
            if (!item.isTextual() && !item.isNumber()) throw bad("CTI_INVALID_ATTRIBUTE");
            String text = item.asText().trim();
            if (text.isEmpty()) continue;
            if (text.length() > 512) throw bad("CTI_ATTRIBUTE_TOO_LONG");
            if ("attack-technique".equals(spec.format())) {
              text = text.toUpperCase(Locale.ROOT);
              if (!ATTACK.matcher(text).matches()) throw bad("CTI_INVALID_ATTACK_TECHNIQUE");
            }
            if (seen.add(text.toLowerCase(Locale.ROOT))) list.add(text);
          }
          if (list.size() > 200) throw bad("CTI_LIST_TOO_LONG");
          return list.isEmpty() ? null : list;
        }
      default:
        throw bad("CTI_INVALID_ATTRIBUTE");
    }
  }

  /** Merge for upserts: incoming scalars win, lists are unioned, absent keys are kept. */
  public static ObjectNode merge(CtiTaxonomy.Kind kind, ObjectNode existing, ObjectNode incoming) {
    ObjectNode out = existing.deepCopy();
    var fields = incoming.fields();
    while (fields.hasNext()) {
      var field = fields.next();
      CtiTaxonomy.Attribute spec = kind.attributes().get(field.getKey());
      if (spec != null && "list".equals(spec.type()) && out.path(field.getKey()).isArray()) {
        ArrayNode list = ((ArrayNode) out.get(field.getKey())).deepCopy();
        Set<String> seen = new HashSet<>();
        list.forEach(item -> seen.add(item.asText().toLowerCase(Locale.ROOT)));
        field.getValue().forEach(item -> {
          if (seen.add(item.asText().toLowerCase(Locale.ROOT))) list.add(item);
        });
        out.set(field.getKey(), list);
      } else out.set(field.getKey(), field.getValue());
    }
    return out;
  }

  /** The dedupe key: lowercased, whitespace-collapsed components named by the taxonomy. */
  public static String naturalKey(CtiTaxonomy.Kind kind, String name, ObjectNode attributes) {
    String spec = kind.naturalKey();
    if (spec.contains("|")) {
      for (String alternative : spec.split("\\|")) {
        String part = component(alternative, name, attributes);
        if (!part.isEmpty()) return alternative + ":" + part;
      }
      throw bad("CTI_NAME_REQUIRED");
    }
    StringBuilder key = new StringBuilder();
    for (String part : spec.split(":")) {
      String value = component(part, name, attributes);
      if (value.isEmpty()) throw bad("name".equals(part) ? "CTI_NAME_REQUIRED" : "CTI_ATTRIBUTE_REQUIRED");
      if (key.length() > 0) key.append(':');
      key.append(value);
    }
    if (key.length() > 1024) throw bad("CTI_KEY_TOO_LONG");
    return key.toString();
  }

  private static String component(String part, String name, ObjectNode attributes) {
    String raw = "name".equals(part) ? name : attributes.path(part).asText("");
    return normalizeKey(raw);
  }

  public static String normalizeKey(String raw) {
    return raw == null ? "" : refang(raw).toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
  }

  /** Display name when none was given, derived from the identifying attributes. */
  public static String defaultName(String kind, ObjectNode attributes) {
    switch (kind) {
      case "watch":
        return attributes.path("watchType").asText("") + " · " + attributes.path("target").asText("");
      case "enrichment":
        return attributes.path("provider").asText("") + " · " + attributes.path("query").asText("");
      case "malware":
        return attributes.path("sha256").asText(attributes.path("family").asText(""));
      default:
        return attributes.path("value").asText("");
    }
  }

  public static Instant instant(String value) {
    if (value == null || value.isBlank()) return null;
    try {
      return OffsetDateTime.parse(value).toInstant();
    } catch (DateTimeParseException ignored) {
      try {
        return Instant.parse(value);
      } catch (DateTimeParseException ignoredAgain) {
        try {
          return LocalDate.parse(value.substring(0, Math.min(10, value.length()))).atStartOfDay(ZoneOffset.UTC).toInstant();
        } catch (DateTimeParseException failure) {
          throw bad("CTI_INVALID_DATE");
        }
      }
    }
  }

  public static List<String> labels(List<String> input) {
    if (input == null) return List.of();
    LinkedHashSet<String> out = new LinkedHashSet<>();
    for (String label : input) {
      if (label == null || label.isBlank()) continue;
      String normalized = label.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", "-");
      if (!LABEL.matcher(normalized).matches()) throw bad("CTI_INVALID_LABEL");
      out.add(normalized);
    }
    if (out.size() > 50) throw bad("CTI_TOO_MANY_LABELS");
    return List.copyOf(out);
  }

  /** RFC 4122 name-based UUID (version 5, SHA-1), as STIX uses for deterministic identifiers. */
  public static UUID uuid5(UUID namespace, String name) {
    try {
      var digest = java.security.MessageDigest.getInstance("SHA-1");
      var buffer = java.nio.ByteBuffer.allocate(16);
      buffer.putLong(namespace.getMostSignificantBits()).putLong(namespace.getLeastSignificantBits());
      digest.update(buffer.array());
      byte[] hash = digest.digest(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      hash[6] = (byte) ((hash[6] & 0x0f) | 0x50);
      hash[8] = (byte) ((hash[8] & 0x3f) | 0x80);
      var bytes = java.nio.ByteBuffer.wrap(hash, 0, 16);
      return new UUID(bytes.getLong(), bytes.getLong());
    } catch (java.security.NoSuchAlgorithmException failure) {
      throw new IllegalStateException(failure);
    }
  }
}
