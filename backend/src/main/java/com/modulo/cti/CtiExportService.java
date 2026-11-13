package com.modulo.cti;

import static com.modulo.cti.CtiTaxonomy.bad;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/**
 * STIX 2.1 and MISP interop for the CTI knowledge base. Every export applies a TLP ceiling, never
 * includes workflow records (leads, watches, enrichment), excludes victims unless asked and then
 * pseudonymizes redacted victims and drops their private fields.
 */
@Service
public class CtiExportService {
  /** STIX 2.1 namespace for deterministic cyber-observable identifiers (spec §2.9). */
  static final UUID STIX_SCO_NAMESPACE = UUID.fromString("00abedb4-aa42-466c-9c01-fed23315a9b7");
  /** Modulo namespace for other deterministic ids (attack patterns, bundles, custom markings). */
  static final UUID MODULO_NAMESPACE = UUID.fromString("6f3c2a7e-1d5b-5c4e-9a8f-2b7d0e1c4a95");
  /** TLP 1.0 marking definitions defined by the STIX 2.1 specification. */
  static final Map<String, String> TLP_MARKINGS =
      Map.of(
          "clear", "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
          "green", "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
          "amber", "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
          "red", "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed");
  static final String AMBER_STRICT_MARKING =
      "marking-definition--" + CtiValues.uuid5(MODULO_NAMESPACE, "tlp:amber+strict");
  static final Pattern SIMPLE_PATTERN =
      Pattern.compile("^\\[(domain-name|ipv4-addr|ipv6-addr|url|email-addr|cryptocurrency-wallet):value\\s*=\\s*'((?:[^'\\\\]|\\\\.)*)'\\]$");
  static final Pattern HASH_PATTERN =
      Pattern.compile("^\\[file:hashes\\.(?:'|\")?(SHA-256|SHA-1|MD5)(?:'|\")?\\s*=\\s*'([0-9a-fA-F]+)'\\]$");

  private final CtiService cti;
  private final CtiTaxonomy taxonomy;
  private final ObjectMapper json;
  private final ObjectMapper canonical;

  public CtiExportService(CtiService cti, CtiTaxonomy taxonomy, ObjectMapper json) {
    this.cti = cti;
    this.taxonomy = taxonomy;
    this.json = json;
    this.canonical = json.copy().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
  }

  public record Options(String tlpCeiling, boolean includeVictims, Set<UUID> scope) {
    public Options {
      tlpCeiling = CtiTaxonomy.tlp(tlpCeiling == null ? "green" : tlpCeiling);
    }
  }

  public record Capsule(Map<String, Object> bundle, String sha256, int objects) {}

  // ------------------------------------------------------------------ selection

  private record Selection(List<Map<String, Object>> objects, List<Map<String, Object>> relationships) {}

  private Selection select(long owner, Options options) {
    int ceiling = CtiTaxonomy.tlpRank(options.tlpCeiling());
    List<Map<String, Object>> objects = new ArrayList<>();
    Set<UUID> kept = new HashSet<>();
    for (var object : cti.allObjects(owner)) {
      String kind = (String) object.get("kind");
      if (!CtiTaxonomy.KNOWLEDGE_KINDS.contains(kind)) continue;
      if ("victim".equals(kind) && !options.includeVictims()) continue;
      if (CtiTaxonomy.tlpRank((String) object.get("tlp")) > ceiling) continue;
      if (options.scope() != null && !options.scope().contains((UUID) object.get("id"))) continue;
      objects.add(object);
      kept.add((UUID) object.get("id"));
    }
    List<Map<String, Object>> relationships = new ArrayList<>();
    for (var rel : cti.allRelationships(owner))
      if (kept.contains((UUID) rel.get("sourceId")) && kept.contains((UUID) rel.get("targetId"))
          && CtiTaxonomy.tlpRank((String) rel.get("tlp")) <= ceiling) relationships.add(rel);
    return new Selection(objects, relationships);
  }

  // ------------------------------------------------------------------ STIX export

  public Map<String, Object> stix(long owner, Options options) {
    return stixBundle(select(owner, options), null);
  }

  private Map<String, Object> stixBundle(Selection selection, Map<String, Object> report) {
    Map<String, Map<String, Object>> out = new LinkedHashMap<>();
    Map<UUID, String> primary = new HashMap<>();
    Set<String> markings = new TreeSet<>();
    for (var object : selection.objects()) {
      for (var stix : stixObjects(object)) {
        out.putIfAbsent((String) stix.get("id"), stix);
        if (!primary.containsKey((UUID) object.get("id"))) primary.put((UUID) object.get("id"), (String) stix.get("id"));
      }
      markings.add((String) object.get("tlp"));
    }
    for (var object : selection.objects()) {
      if (!"actor".equals(object.get("kind")) && !"campaign".equals(object.get("kind"))) continue;
      for (JsonNode technique : ((JsonNode) object.get("attributes")).path("ttps")) {
        String pattern = attackPattern(technique.asText(), out);
        Map<String, Object> rel = base("relationship",
            "relationship--" + CtiValues.uuid5(MODULO_NAMESPACE, object.get("id") + ":uses:" + technique.asText()), object);
        rel.put("relationship_type", "uses");
        rel.put("source_ref", primary.get((UUID) object.get("id")));
        rel.put("target_ref", pattern);
        out.put((String) rel.get("id"), rel);
      }
    }
    for (var rel : selection.relationships()) {
      String source = primary.get((UUID) rel.get("sourceId"));
      String target = primary.get((UUID) rel.get("targetId"));
      if (source == null || target == null) continue;
      Map<String, Object> stix = new LinkedHashMap<>();
      stix.put("type", "relationship");
      stix.put("spec_version", "2.1");
      stix.put("id", "relationship--" + rel.get("id"));
      stix.put("created", stamp((String) rel.get("createdAt")));
      stix.put("modified", stamp((String) rel.get("updatedAt")));
      stix.put("relationship_type", rel.get("type"));
      stix.put("source_ref", source);
      stix.put("target_ref", target);
      if (rel.get("confidence") != null) stix.put("confidence", rel.get("confidence"));
      if (rel.get("description") != null && !((String) rel.get("description")).isBlank()) stix.put("description", rel.get("description"));
      if (rel.get("firstSeen") != null) stix.put("start_time", stamp((String) rel.get("firstSeen")));
      if (rel.get("lastSeen") != null) stix.put("stop_time", stamp((String) rel.get("lastSeen")));
      stix.put("object_marking_refs", List.of(marking((String) rel.get("tlp"))));
      markings.add((String) rel.get("tlp"));
      out.put((String) stix.get("id"), stix);
    }
    if (report != null) {
      List<String> refs = new ArrayList<>(out.keySet());
      if (refs.isEmpty()) refs.add(marking("clear"));
      report.put("object_refs", refs);
      markings.add(tlpOf(report));
      out.put((String) report.get("id"), report);
    }
    List<Object> objects = new ArrayList<>();
    for (String tlp : markings) objects.add(markingDefinition(tlp));
    objects.addAll(out.values());
    Map<String, Object> bundle = new LinkedHashMap<>();
    bundle.put("type", "bundle");
    bundle.put("id", "bundle--" + CtiValues.uuid5(MODULO_NAMESPACE, canonicalJson(objects)));
    bundle.put("objects", objects);
    return bundle;
  }

  private List<Map<String, Object>> stixObjects(Map<String, Object> object) {
    String kind = (String) object.get("kind");
    JsonNode a = (JsonNode) object.get("attributes");
    List<Map<String, Object>> out = new ArrayList<>();
    switch (kind) {
      case "actor": {
        Map<String, Object> s = sdo("threat-actor", object);
        s.put("threat_actor_types", List.of("unknown"));
        list(a, "aliases", s, "aliases");
        put(a, "motivation", s, "primary_motivation");
        put(a, "sophistication", s, "sophistication");
        put(a, "resourceLevel", s, "resource_level");
        list(a, "goals", s, "goals");
        seen(object, s, "first_seen", "last_seen");
        put(a, "attribution", s, "x_modulo_attribution");
        list(a, "auditThreatRefs", s, "x_modulo_audit_threat_refs");
        out.add(s);
        break;
      }
      case "campaign": {
        boolean intrusionSet = "intrusion-set".equals(a.path("clusterType").asText());
        Map<String, Object> s = sdo(intrusionSet ? "intrusion-set" : "campaign", object);
        put(a, "objective", s, intrusionSet ? "x_modulo_objective" : "objective");
        put(a, "branch", s, "x_modulo_branch");
        put(a, "clusterType", s, "x_modulo_cluster_type");
        seen(object, s, "first_seen", "last_seen");
        out.add(s);
        break;
      }
      case "malware": {
        Map<String, Object> s = sdo("malware", object);
        String role = a.path("role").asText("");
        s.put("is_family", "family".equals(role) || (!a.has("sha256") && !"sample".equals(role)));
        s.put("malware_types", List.of(malwareType(role)));
        list(a, "capabilities", s, "x_modulo_capabilities");
        put(a, "family", s, "x_modulo_family");
        put(a, "role", s, "x_modulo_role");
        seen(object, s, "first_seen", "last_seen");
        if (a.has("sha256")) {
          Map<String, Object> file = sco("file", object, Map.of("hashes", Map.of("SHA-256", a.get("sha256").asText())));
          file.put("hashes", Map.of("SHA-256", a.get("sha256").asText()));
          s.put("sample_refs", List.of(file.get("id")));
          out.add(s);
          out.add(file);
        } else out.add(s);
        break;
      }
      case "indicator": {
        Map<String, Object> s = sdo("indicator", object);
        String type = a.path("indicatorType").asText();
        String value = a.path("value").asText();
        String patternType = Set.of("yara", "sigma").contains(type) ? type : "stix";
        s.put("pattern_type", patternType);
        s.put("pattern", a.hasNonNull("pattern") ? a.get("pattern").asText() : "stix".equals(patternType) ? pattern(type, value) : value);
        s.put("indicator_types", List.of("malicious-activity"));
        s.put("valid_from", a.has("validFrom") ? date(a.get("validFrom").asText()) : s.get("created"));
        if (a.has("validUntil")) s.put("valid_until", date(a.get("validUntil").asText()));
        put(a, "source", s, "x_modulo_source");
        s.put("x_modulo_indicator_type", type);
        s.put("x_modulo_value", value);
        out.add(s);
        break;
      }
      case "infrastructure": {
        Map<String, Object> s = sdo("infrastructure", object);
        String infraKind = a.path("infraKind").asText();
        s.put("infrastructure_types", List.of(infrastructureType(infraKind)));
        s.put("x_modulo_infra_kind", infraKind);
        s.put("x_modulo_value", a.path("value").asText());
        s.put("x_modulo_status", object.get("status"));
        put(a, "hosting", s, "x_modulo_hosting");
        put(a, "asn", s, "x_modulo_asn");
        put(a, "registrar", s, "x_modulo_registrar");
        seen(object, s, "first_seen", "last_seen");
        out.add(s);
        Map<String, Object> observable = observable(a.path("value").asText(), object);
        if (observable != null) {
          out.add(observable);
          Map<String, Object> rel = base("relationship", "relationship--" + CtiValues.uuid5(MODULO_NAMESPACE, object.get("id") + ":consists-of"), object);
          rel.put("relationship_type", "consists-of");
          rel.put("source_ref", s.get("id"));
          rel.put("target_ref", observable.get("id"));
          out.add(rel);
        }
        break;
      }
      case "identity": {
        String type = a.path("identityType").asText();
        String value = a.path("value").asText();
        Map<String, Object> s;
        if ("email".equals(type)) s = sco("email-addr", object, Map.of("value", value));
        else if ("wallet".equals(type)) s = sco("cryptocurrency-wallet", object, Map.of("value", value));
        else {
          Map<String, Object> contributing = new TreeMap<>();
          contributing.put("account_login", value);
          if (a.has("platform")) contributing.put("account_type", a.get("platform").asText().toLowerCase(Locale.ROOT));
          s = sco("user-account", object, contributing);
          s.put("account_login", value);
          if (a.has("platform")) s.put("account_type", a.get("platform").asText().toLowerCase(Locale.ROOT));
          s.put("display_name", object.get("name"));
        }
        if (!s.containsKey("account_login")) s.put("value", value);
        s.put("x_modulo_identity_type", type);
        put(a, "platform", s, "x_modulo_platform");
        put(a, "chain", s, "x_modulo_chain");
        if (object.get("confidence") != null) s.put("x_modulo_confidence", object.get("confidence"));
        out.add(s);
        break;
      }
      case "victim": {
        boolean redacted = a.path("redacted").asBoolean(true);
        Map<String, Object> s = sdo("identity", object);
        s.put("identity_class", "unknown");
        if (redacted) {
          s.put("name", "Redacted victim " + CtiValues.uuid5(MODULO_NAMESPACE, object.get("id").toString()).toString().substring(0, 8));
          s.remove("description");
          s.remove("labels");
        }
        put(a, "exposureType", s, "x_modulo_exposure_type");
        if (!redacted) put(a, "sector", s, "x_modulo_sector");
        s.put("x_modulo_redacted", redacted);
        out.add(s);
        break;
      }
      default:
        break;
    }
    return out;
  }

  private Map<String, Object> base(String type, String id, Map<String, Object> object) {
    Map<String, Object> s = new LinkedHashMap<>();
    s.put("type", type);
    s.put("spec_version", "2.1");
    s.put("id", id);
    s.put("created", stamp((String) object.get("createdAt")));
    s.put("modified", stamp((String) object.get("updatedAt")));
    s.put("object_marking_refs", List.of(marking((String) object.get("tlp"))));
    return s;
  }

  private Map<String, Object> sdo(String type, Map<String, Object> object) {
    Map<String, Object> s = base(type, type + "--" + object.get("id"), object);
    s.put("name", object.get("name"));
    String description = (String) object.get("description");
    if (description != null && !description.isBlank()) s.put("description", description);
    if (object.get("confidence") != null) s.put("confidence", object.get("confidence"));
    List<String> labels = CtiService.strings((JsonNode) object.get("labels"));
    if (!labels.isEmpty()) s.put("labels", labels);
    s.put("x_modulo_id", object.get("id").toString());
    s.put("x_modulo_kind", object.get("kind"));
    s.put("x_modulo_status", object.get("status"));
    return s;
  }

  /** Cyber-observable with a deterministic id derived from its id-contributing properties. */
  private Map<String, Object> sco(String type, Map<String, Object> object, Map<String, Object> contributing) {
    Map<String, Object> s = new LinkedHashMap<>();
    s.put("type", type);
    s.put("spec_version", "2.1");
    s.put("id", type + "--" + CtiValues.uuid5(STIX_SCO_NAMESPACE, canonicalJson(new TreeMap<>(contributing))));
    s.put("object_marking_refs", List.of(marking((String) object.get("tlp"))));
    if ("identity".equals(object.get("kind"))) {
      s.put("x_modulo_id", object.get("id").toString());
      s.put("x_modulo_kind", "identity");
      s.put("x_modulo_name", object.get("name"));
      s.put("x_modulo_status", object.get("status"));
    }
    return s;
  }

  private Map<String, Object> observable(String value, Map<String, Object> object) {
    String type = CtiValues.inferType(value);
    String sco = switch (type) {
      case "ipv4" -> "ipv4-addr";
      case "ipv6" -> "ipv6-addr";
      case "url" -> "url";
      case "domain" -> "domain-name";
      default -> null;
    };
    if (sco == null) return null;
    Map<String, Object> s = sco(sco, object, Map.of("value", value));
    s.put("value", value);
    return s;
  }

  private String attackPattern(String technique, Map<String, Map<String, Object>> out) {
    String id = "attack-pattern--" + CtiValues.uuid5(MODULO_NAMESPACE, "mitre-attack:" + technique);
    if (!out.containsKey(id)) {
      Map<String, Object> s = new LinkedHashMap<>();
      s.put("type", "attack-pattern");
      s.put("spec_version", "2.1");
      s.put("id", id);
      s.put("created", "2017-05-31T21:30:00.000Z");
      s.put("modified", "2017-05-31T21:30:00.000Z");
      s.put("name", technique);
      s.put("external_references", List.of(Map.of(
          "source_name", "mitre-attack", "external_id", technique,
          "url", "https://attack.mitre.org/techniques/" + technique.replace('.', '/') + "/")));
      s.put("object_marking_refs", List.of(marking("clear")));
      out.put(id, s);
    }
    return id;
  }

  static String marking(String tlp) {
    return "amber+strict".equals(tlp) ? AMBER_STRICT_MARKING : TLP_MARKINGS.get(tlp);
  }

  static Map<String, Object> markingDefinition(String tlp) {
    Map<String, Object> s = new LinkedHashMap<>();
    s.put("type", "marking-definition");
    s.put("spec_version", "2.1");
    s.put("id", marking(tlp));
    s.put("created", "2017-01-20T00:00:00.000Z");
    if ("amber+strict".equals(tlp)) {
      s.put("name", "TLP:AMBER+STRICT");
      s.put("definition_type", "statement");
      s.put("definition", Map.of("statement", "TLP:AMBER+STRICT"));
    } else {
      String label = "clear".equals(tlp) ? "white" : tlp;
      s.put("name", "TLP:" + label.toUpperCase(Locale.ROOT));
      s.put("definition_type", "tlp");
      s.put("definition", Map.of("tlp", label));
    }
    return s;
  }

  static String pattern(String type, String value) {
    String v = value.replace("\\", "\\\\").replace("'", "\\'");
    return switch (type) {
      case "domain" -> "[domain-name:value = '" + v + "']";
      case "ipv4" -> "[ipv4-addr:value = '" + v + "']";
      case "ipv6" -> "[ipv6-addr:value = '" + v + "']";
      case "url" -> "[url:value = '" + v + "']";
      case "email" -> "[email-addr:value = '" + v + "']";
      case "sha256" -> "[file:hashes.'SHA-256' = '" + v + "']";
      case "sha1" -> "[file:hashes.'SHA-1' = '" + v + "']";
      case "md5" -> "[file:hashes.MD5 = '" + v + "']";
      case "filename" -> "[file:name = '" + v + "']";
      case "wallet" -> "[cryptocurrency-wallet:value = '" + v + "']";
      case "stix-pattern" -> value;
      default -> "[x-modulo-observable:value = '" + v + "']";
    };
  }

  static String malwareType(String role) {
    return switch (role) {
      case "loader" -> "downloader";
      case "dropper" -> "dropper";
      case "stealer" -> "spyware";
      case "backdoor" -> "backdoor";
      case "rat" -> "remote-access-trojan";
      case "wiper" -> "wiper";
      default -> "unknown";
    };
  }

  static String infrastructureType(String kind) {
    return switch (kind) {
      case "c2", "dead-drop" -> "command-and-control";
      case "blob-host", "repository" -> "hosting-malware";
      default -> "unknown";
    };
  }

  private static void put(JsonNode a, String key, Map<String, Object> s, String target) {
    if (a.hasNonNull(key)) s.put(target, a.get(key).isBoolean() ? a.get(key).asBoolean() : a.get(key).asText());
  }

  private static void list(JsonNode a, String key, Map<String, Object> s, String target) {
    if (a.path(key).isArray() && a.get(key).size() > 0) s.put(target, CtiService.strings(a.get(key)));
  }

  private static void seen(Map<String, Object> object, Map<String, Object> s, String first, String last) {
    if (object.get("firstSeen") != null) s.put(first, stamp((String) object.get("firstSeen")));
    if (object.get("lastSeen") != null) s.put(last, stamp((String) object.get("lastSeen")));
  }

  /** STIX timestamps: UTC with millisecond precision. */
  static String stamp(String iso) {
    Instant instant = iso == null ? Instant.EPOCH : Instant.parse(iso);
    return java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC).format(instant);
  }

  private static String date(String day) {
    return stamp(LocalDate.parse(day).atStartOfDay(ZoneOffset.UTC).toInstant().toString());
  }

  private static String tlpOf(Map<String, Object> stix) {
    Object refs = stix.get("object_marking_refs");
    if (refs instanceof List<?> list && !list.isEmpty()) {
      for (var entry : TLP_MARKINGS.entrySet()) if (entry.getValue().equals(list.get(0))) return entry.getKey();
      if (AMBER_STRICT_MARKING.equals(list.get(0))) return "amber+strict";
    }
    return "amber";
  }

  String canonicalJson(Object value) {
    try {
      return canonical.writeValueAsString(canonical.valueToTree(value));
    } catch (JsonProcessingException failure) {
      throw new IllegalStateException(failure);
    }
  }

  // ------------------------------------------------------------------ disclosure capsule

  /**
   * Builds the shareable capsule for a disclosure: a STIX bundle with a {@code report} for the
   * disclosure, the objects it concerns and their one-hop knowledge neighbourhood, under the
   * disclosure's TLP ceiling. The SHA-256 of the returned bytes is stamped on the disclosure.
   */
  public Capsule capsule(long owner, UUID disclosureId) {
    Map<String, Object> disclosure = cti.detail(owner, disclosureId);
    if (!"disclosure".equals(disclosure.get("kind"))) throw bad("CTI_NOT_A_DISCLOSURE");
    JsonNode a = (JsonNode) disclosure.get("attributes");
    String ceiling = a.path("tlpCeiling").asText("green");
    boolean victims = a.path("includeVictims").asBoolean(false);
    Set<UUID> direct = new LinkedHashSet<>();
    for (var rel : relationshipsOf(disclosure))
      if ("concerns".equals(rel.get("type")) && "outgoing".equals(rel.get("direction")))
        direct.add((UUID) ((Map<?, ?>) rel.get("other")).get("id"));
    if (direct.isEmpty()) throw bad("CTI_DISCLOSURE_EMPTY");
    Set<UUID> scope = new LinkedHashSet<>(direct);
    for (UUID id : direct) {
      for (var rel : relationshipsOf(cti.detail(owner, id))) {
        Map<?, ?> other = (Map<?, ?>) rel.get("other");
        if (CtiTaxonomy.KNOWLEDGE_KINDS.contains((String) other.get("kind"))) scope.add((UUID) other.get("id"));
      }
    }
    Selection selection = select(owner, new Options(ceiling, victims, scope));
    Map<String, Object> report = sdo("report", disclosure);
    report.remove("x_modulo_status");
    report.put("report_types", List.of("threat-report"));
    report.put("published", stamp((String) disclosure.get("updatedAt")));
    report.put("object_marking_refs", List.of(marking(ceiling)));
    put(a, "recipient", report, "x_modulo_recipient");
    put(a, "disclosureType", report, "x_modulo_disclosure_type");
    put(a, "reference", report, "x_modulo_reference");
    report.put("x_modulo_tlp_ceiling", ceiling);
    Map<String, Object> bundle = stixBundle(selection, report);
    String sha = sha256(canonicalJson(bundle));
    cti.stamp(owner, disclosureId, Map.of("capsuleSha256", sha, "capsuleAt", Instant.now().toString()), "capsule-built",
        Map.of("sha256", sha, "objects", ((List<?>) bundle.get("objects")).size(), "tlpCeiling", ceiling));
    return new Capsule(bundle, sha, ((List<?>) bundle.get("objects")).size());
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> relationshipsOf(Map<String, Object> detail) {
    return (List<Map<String, Object>>) detail.get("relationships");
  }

  static String sha256(String value) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException failure) {
      throw new IllegalStateException(failure);
    }
  }

  // ------------------------------------------------------------------ MISP export

  public Map<String, Object> misp(long owner, Options options, String info) {
    Selection selection = select(owner, new Options(options.tlpCeiling(), false, options.scope()));
    List<Map<String, Object>> attributes = new ArrayList<>();
    List<Map<String, Object>> tags = new ArrayList<>(List.of(Map.of("name", "tlp:" + options.tlpCeiling())));
    for (var object : selection.objects()) {
      JsonNode a = (JsonNode) object.get("attributes");
      String kind = (String) object.get("kind");
      String value = a.path("value").asText("");
      switch (kind) {
        case "indicator" -> {
          String type = mispType(a.path("indicatorType").asText(), value);
          attributes.add(attribute(object, type, category(type), value, a.path("toIds").asBoolean(true), ""));
        }
        case "infrastructure" -> {
          String type = mispType(CtiValues.inferType(value), value);
          attributes.add(attribute(object, type, category(type), value, false, a.path("infraKind").asText()));
        }
        case "malware" -> {
          if (a.has("sha256"))
            attributes.add(attribute(object, "sha256", "Payload delivery", a.get("sha256").asText(), true, "sample"));
          attributes.add(attribute(object, "text", "Other", (String) object.get("name"), false, "malware"));
        }
        case "identity" -> {
          String type = switch (a.path("identityType").asText()) {
            case "email" -> "email-src";
            case "wallet" -> mispType("wallet", value);
            default -> "text";
          };
          String category = "email-src".equals(type) ? "Network activity" : "btc".equals(type) ? "Financial fraud" : "Other";
          attributes.add(attribute(object, type, category, value, false, a.path("identityType").asText() + " " + a.path("platform").asText("")));
        }
        case "actor" -> {
          attributes.add(attribute(object, "threat-actor", "Attribution", (String) object.get("name"), false, ""));
          tags.add(Map.of("name", "misp-galaxy:threat-actor=\"" + ((String) object.get("name")).replace("\"", "'") + "\""));
        }
        case "campaign" -> attributes.add(attribute(object, "campaign-name", "Attribution", (String) object.get("name"), false, ""));
        default -> {}
      }
    }
    Map<String, Object> event = new LinkedHashMap<>();
    String title = info == null || info.isBlank() ? "Modulo CTI export" : info;
    event.put("uuid", CtiValues.uuid5(MODULO_NAMESPACE, "misp:" + owner + ":" + title).toString());
    event.put("info", title);
    event.put("date", LocalDate.now(ZoneOffset.UTC).toString());
    event.put("threat_level_id", "2");
    event.put("analysis", "1");
    event.put("distribution", "0");
    event.put("published", false);
    event.put("Tag", tags);
    event.put("Attribute", attributes);
    return Map.of("Event", event);
  }

  private Map<String, Object> attribute(Map<String, Object> object, String type, String category, String value, boolean toIds, String note) {
    Map<String, Object> a = new LinkedHashMap<>();
    a.put("uuid", CtiValues.uuid5(MODULO_NAMESPACE, object.get("id") + ":" + type + ":" + value).toString());
    a.put("type", type);
    a.put("category", category);
    a.put("value", value);
    a.put("to_ids", toIds);
    String comment = ((String) object.get("name") + (note.isBlank() ? "" : " · " + note.trim())).trim();
    a.put("comment", comment.length() > 1000 ? comment.substring(0, 1000) : comment);
    if (object.get("firstSeen") != null) a.put("first_seen", object.get("firstSeen"));
    if (object.get("lastSeen") != null) a.put("last_seen", object.get("lastSeen"));
    a.put("Tag", List.of(Map.of("name", "tlp:" + object.get("tlp"))));
    return a;
  }

  static String mispType(String type, String value) {
    return switch (type) {
      case "domain" -> "domain";
      case "ipv4", "ipv6" -> "ip-dst";
      case "url" -> "url";
      case "email" -> "email-src";
      case "sha256", "sha1", "md5", "yara", "sigma", "filename" -> type;
      case "stix-pattern" -> "stix2-pattern";
      case "wallet" -> value.matches("^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$") ? "btc" : "text";
      default -> "text";
    };
  }

  static String category(String type) {
    return switch (type) {
      case "domain", "ip-dst", "url", "email-src" -> "Network activity";
      case "sha256", "sha1", "md5", "filename" -> "Payload delivery";
      case "yara", "sigma", "stix2-pattern" -> "Artifacts dropped";
      case "btc" -> "Financial fraud";
      default -> "Other";
    };
  }

  // ------------------------------------------------------------------ STIX import

  /** Maps a STIX 2.1 bundle (ours or OpenCTI-style) onto an idempotent ingest batch. */
  public Map<String, Object> importStix(long owner, JsonNode bundle) {
    if (bundle == null || !"bundle".equals(bundle.path("type").asText()) || !bundle.path("objects").isArray())
      throw bad("CTI_INVALID_STIX_BUNDLE");
    JsonNode objects = bundle.get("objects");
    if (objects.size() > 10000) throw bad("CTI_STIX_BUNDLE_TOO_LARGE");
    Map<String, JsonNode> byId = new HashMap<>();
    objects.forEach(o -> byId.put(o.path("id").asText(), o));
    Set<String> represented = new HashSet<>();
    Map<String, List<String>> techniques = new HashMap<>();
    for (JsonNode o : objects) {
      if ("relationship".equals(o.path("type").asText()) && "consists-of".equals(o.path("relationship_type").asText()))
        represented.add(o.path("target_ref").asText());
      if ("malware".equals(o.path("type").asText())) o.path("sample_refs").forEach(ref -> represented.add(ref.asText()));
      if ("relationship".equals(o.path("type").asText()) && "uses".equals(o.path("relationship_type").asText())) {
        JsonNode target = byId.get(o.path("target_ref").asText());
        if (target != null && "attack-pattern".equals(target.path("type").asText())) {
          for (JsonNode ref : target.path("external_references"))
            if ("mitre-attack".equals(ref.path("source_name").asText()) && ref.hasNonNull("external_id"))
              techniques.computeIfAbsent(o.path("source_ref").asText(), k -> new ArrayList<>()).add(ref.get("external_id").asText());
        }
      }
    }
    List<CtiService.IngestObject> items = new ArrayList<>();
    Map<String, Integer> skipped = new TreeMap<>();
    Set<String> mapped = new HashSet<>();
    for (JsonNode o : objects) {
      String type = o.path("type").asText();
      if (Set.of("relationship", "marking-definition", "attack-pattern").contains(type)) continue;
      if (represented.contains(o.path("id").asText())) continue;
      CtiService.IngestObject item = toIngest(o, byId, techniques.getOrDefault(o.path("id").asText(), List.of()));
      if (item == null) {
        skipped.merge(type, 1, Integer::sum);
        continue;
      }
      items.add(item);
      mapped.add(o.path("id").asText());
    }
    List<CtiService.IngestRelationship> relationships = new ArrayList<>();
    Map<String, String> kindOf = new HashMap<>();
    items.forEach(item -> kindOf.put(item.ref(), item.kind()));
    for (JsonNode o : objects) {
      if (!"relationship".equals(o.path("type").asText())) continue;
      String type = o.path("relationship_type").asText();
      String source = o.path("source_ref").asText();
      String target = o.path("target_ref").asText();
      if (!mapped.contains(source) || !mapped.contains(target) || source.equals(target)
          || !taxonomy.relationshipAllowed(type, kindOf.get(source), kindOf.get(target))) {
        if (!"consists-of".equals(type) && !target.startsWith("attack-pattern--")) skipped.merge("relationship", 1, Integer::sum);
        continue;
      }
      relationships.add(new CtiService.IngestRelationship(json.getNodeFactory().textNode(source), json.getNodeFactory().textNode(target),
          type, o.hasNonNull("confidence") ? Integer.valueOf(o.get("confidence").asInt()) : null, o.path("description").asText(null),
          tlpFrom(o), o.path("start_time").asText(null), o.path("stop_time").asText(null)));
    }
    Map<String, Object> result = new LinkedHashMap<>(cti.ingest(owner, new CtiService.IngestBatch("stix-import", items, relationships, null)));
    result.put("skipped", skipped);
    return result;
  }

  private CtiService.IngestObject toIngest(JsonNode o, Map<String, JsonNode> byId, List<String> ttps) {
    String type = o.path("type").asText();
    ObjectNode a = json.createObjectNode();
    String kind;
    String name = o.path("name").asText(null);
    String status = o.path("x_modulo_status").asText(null);
    switch (type) {
      case "threat-actor" -> {
        kind = "actor";
        copyList(o, "aliases", a, "aliases");
        copy(o, "primary_motivation", a, "motivation", taxonomy.kind("actor"));
        copy(o, "sophistication", a, "sophistication", taxonomy.kind("actor"));
        copy(o, "resource_level", a, "resourceLevel", taxonomy.kind("actor"));
        copyList(o, "goals", a, "goals");
        copy(o, "x_modulo_attribution", a, "attribution", null);
        copyList(o, "x_modulo_audit_threat_refs", a, "auditThreatRefs");
        ArrayNode list = a.putArray("ttps");
        Set<String> seen = new HashSet<>();
        for (String technique : ttps)
          if (CtiValues.ATTACK.matcher(technique.toUpperCase(Locale.ROOT)).matches() && seen.add(technique)) list.add(technique);
        if (list.isEmpty()) a.remove("ttps");
      }
      case "campaign", "intrusion-set" -> {
        kind = "campaign";
        a.put("clusterType", "intrusion-set".equals(type) ? "intrusion-set" : o.path("x_modulo_cluster_type").asText("campaign"));
        copy(o, "objective", a, "objective", null);
        copy(o, "x_modulo_objective", a, "objective", null);
        copy(o, "x_modulo_branch", a, "branch", null);
      }
      case "malware" -> {
        kind = "malware";
        String role = o.path("x_modulo_role").asText(o.path("is_family").asBoolean(true) ? "family" : "sample");
        if (taxonomy.kind("malware").attributes().get("role").options().contains(role)) a.put("role", role);
        copy(o, "x_modulo_family", a, "family", null);
        copyList(o, "x_modulo_capabilities", a, "capabilities");
        for (JsonNode ref : o.path("sample_refs")) {
          JsonNode file = byId.get(ref.asText());
          if (file != null && file.path("hashes").hasNonNull("SHA-256")) {
            a.put("sha256", file.path("hashes").get("SHA-256").asText().toLowerCase(Locale.ROOT));
            break;
          }
        }
      }
      case "indicator" -> {
        kind = "indicator";
        String pattern = o.path("pattern").asText("");
        String patternType = o.path("pattern_type").asText("stix");
        String indicatorType = o.path("x_modulo_indicator_type").asText(null);
        String value = o.path("x_modulo_value").asText(null);
        if (indicatorType == null || value == null) {
          Matcher simple = SIMPLE_PATTERN.matcher(pattern.trim());
          Matcher hash = HASH_PATTERN.matcher(pattern.trim());
          if (Set.of("yara", "sigma").contains(patternType)) {
            indicatorType = patternType;
            value = pattern;
          } else if (simple.matches()) {
            indicatorType = switch (simple.group(1)) {
              case "domain-name" -> "domain";
              case "ipv4-addr" -> "ipv4";
              case "ipv6-addr" -> "ipv6";
              case "email-addr" -> "email";
              case "cryptocurrency-wallet" -> "wallet";
              default -> "url";
            };
            value = simple.group(2).replace("\\'", "'").replace("\\\\", "\\");
          } else if (hash.matches()) {
            indicatorType = hash.group(1).replace("-", "").toLowerCase(Locale.ROOT);
            value = hash.group(2).toLowerCase(Locale.ROOT);
          } else {
            indicatorType = "stix-pattern";
            value = pattern;
          }
        } else a.put("pattern", pattern);
        if (value == null || value.isBlank()) return null;
        a.put("indicatorType", indicatorType);
        a.put("value", value);
        if (o.hasNonNull("valid_from")) a.put("validFrom", o.get("valid_from").asText().substring(0, 10));
        if (o.hasNonNull("valid_until")) a.put("validUntil", o.get("valid_until").asText().substring(0, 10));
        copy(o, "x_modulo_source", a, "source", null);
      }
      case "infrastructure" -> {
        kind = "infrastructure";
        String infraKind = o.path("x_modulo_infra_kind").asText(null);
        if (infraKind == null) {
          String stixType = o.path("infrastructure_types").path(0).asText("unknown");
          infraKind = "command-and-control".equals(stixType) ? "c2" : "hosting-malware".equals(stixType) ? "blob-host" : "other";
        }
        a.put("infraKind", infraKind);
        String value = o.path("x_modulo_value").asText(null);
        if (value == null) {
          for (JsonNode rel : byId.values())
            if ("consists-of".equals(rel.path("relationship_type").asText()) && o.path("id").asText().equals(rel.path("source_ref").asText())) {
              JsonNode target = byId.get(rel.path("target_ref").asText());
              if (target != null && target.hasNonNull("value")) value = target.get("value").asText();
            }
        }
        a.put("value", value == null ? o.path("name").asText("") : value);
        copy(o, "x_modulo_hosting", a, "hosting", null);
        copy(o, "x_modulo_asn", a, "asn", null);
        copy(o, "x_modulo_registrar", a, "registrar", null);
        if (status != null && !taxonomy.kind("infrastructure").statuses().contains(status)) status = null;
      }
      case "domain-name", "ipv4-addr", "ipv6-addr", "url" -> {
        kind = "infrastructure";
        a.put("infraKind", "domain-name".equals(type) ? "domain" : "url".equals(type) ? "url" : "ip");
        a.put("value", o.path("value").asText(""));
        name = null;
        status = "unknown";
      }
      case "email-addr", "cryptocurrency-wallet", "user-account" -> {
        kind = "identity";
        String identityType = o.path("x_modulo_identity_type").asText(
            "email-addr".equals(type) ? "email" : "cryptocurrency-wallet".equals(type) ? "wallet" : "account");
        a.put("identityType", identityType);
        a.put("value", o.hasNonNull("value") ? o.get("value").asText() : o.path("account_login").asText(o.path("user_id").asText("")));
        copy(o, "x_modulo_platform", a, "platform", null);
        if (!a.has("platform") && o.hasNonNull("account_type")) a.put("platform", o.get("account_type").asText());
        copy(o, "x_modulo_chain", a, "chain", null);
        name = o.path("x_modulo_name").asText(null);
      }
      case "file" -> {
        if (!o.path("hashes").hasNonNull("SHA-256")) return null;
        kind = "malware";
        a.put("role", "sample");
        a.put("sha256", o.path("hashes").get("SHA-256").asText().toLowerCase(Locale.ROOT));
        name = o.path("name").asText(null);
      }
      case "identity" -> {
        if (!"victim".equals(o.path("x_modulo_kind").asText())) return null;
        kind = "victim";
        a.put("redacted", o.path("x_modulo_redacted").asBoolean(true));
        copy(o, "x_modulo_exposure_type", a, "exposureType", taxonomy.kind("victim"));
        copy(o, "x_modulo_sector", a, "sector", null);
      }
      default -> {
        return null;
      }
    }
    if (a.has("value") && a.get("value").asText().isBlank()) return null;
    if (status != null && !taxonomy.kind(kind).statuses().contains(status)) status = null;
    Integer confidence = o.hasNonNull("confidence") ? Integer.valueOf(o.get("confidence").asInt())
        : o.hasNonNull("x_modulo_confidence") ? Integer.valueOf(o.get("x_modulo_confidence").asInt()) : null;
    List<String> labels = new ArrayList<>();
    o.path("labels").forEach(label -> labels.add(label.asText()));
    return new CtiService.IngestObject(o.path("id").asText(), kind, name, status, tlpFrom(o), confidence,
        o.path("description").asText(null), a, labels.isEmpty() ? null : sanitizeLabels(labels),
        o.path("first_seen").asText(null), o.path("last_seen").asText(null));
  }

  private static List<String> sanitizeLabels(List<String> labels) {
    List<String> out = new ArrayList<>();
    for (String label : labels) {
      String normalized = label.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9:._/+-]+", "-").replaceAll("^-+", "");
      if (!normalized.isEmpty() && normalized.length() <= 64 && out.size() < 50) out.add(normalized);
    }
    return out;
  }

  private static String tlpFrom(JsonNode o) {
    for (JsonNode ref : o.path("object_marking_refs")) {
      for (var entry : TLP_MARKINGS.entrySet()) if (entry.getValue().equals(ref.asText())) return entry.getKey();
      if (AMBER_STRICT_MARKING.equals(ref.asText())) return "amber+strict";
      // OASIS TLP 2.0 extension markings
      switch (ref.asText()) {
        case "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": return "clear";
        case "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": return "green";
        case "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": return "amber";
        case "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": return "amber+strict";
        case "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": return "red";
        default: break;
      }
    }
    return null;
  }

  private static void copy(JsonNode o, String from, ObjectNode a, String to, CtiTaxonomy.Kind kind) {
    if (!o.hasNonNull(from)) return;
    String value = o.get(from).asText();
    if (kind != null) {
      CtiTaxonomy.Attribute spec = kind.attributes().get(to);
      if (spec != null && "select".equals(spec.type()) && !spec.options().contains(value)) return;
    }
    a.put(to, value);
  }

  private static void copyList(JsonNode o, String from, ObjectNode a, String to) {
    if (o.path(from).isArray() && o.get(from).size() > 0) a.set(to, o.get(from).deepCopy());
  }
}
