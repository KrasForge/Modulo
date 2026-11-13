package com.modulo.cti;

import static com.modulo.cti.CtiTaxonomy.bad;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.modulo.remote.RemoteCredentialStore;
import com.modulo.remote.SafeHttpFetcher;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * One-click OSINT connectors. Each lookup is logged as an enrichment record linked to the record it
 * enriched; observables it discovers (hostnames, resolutions) are ingested and linked, capped per
 * lookup. A lookup repeated within ten minutes returns the logged result instead of calling the
 * provider again, unless forced.
 *
 * <p>Providers: crt.sh (certificate transparency), urlscan.io (search; an optional API key is the
 * user's {@code urlscanApiKey} remote credential), Mnemonic passive DNS, and blockchain explorers
 * (TRONSCAN, mempool.space, Blockscout). Every request goes through {@link SafeHttpFetcher}.
 */
@Service
public class CtiEnrichmentService {
  static final int MAX_FINDINGS = 50;
  static final Duration REUSE_WINDOW = Duration.ofMinutes(10);
  static final Pattern TRON = Pattern.compile("^T[1-9A-HJ-NP-Za-km-z]{33}$");
  static final Pattern BITCOIN = Pattern.compile("^(bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$");
  static final Pattern ETHEREUM = Pattern.compile("^0x[0-9a-fA-F]{40}$");

  /** Outbound GET; the default is the SSRF-safe fetcher, tests substitute a stub. */
  @FunctionalInterface
  public interface Fetcher {
    SafeHttpFetcher.Response get(String url, Map<String, String> headers);
  }

  /** What a provider learned: a summary, a human link, and observables to ingest. */
  record Outcome(String summary, String resultUrl, List<CtiService.IngestObject> findings,
      List<CtiService.IngestRelationship> relationships) {}

  /** The observable a record exposes to connectors. */
  record Observable(String type, String value) {}

  public static final List<String> PROVIDERS = List.of("crt.sh", "urlscan", "passive-dns", "blockchain-explorer");

  private final CtiService cti;
  private final Fetcher fetcher;
  private final RemoteCredentialStore credentials;
  private final ObjectMapper json = new ObjectMapper();

  @Autowired
  public CtiEnrichmentService(CtiService cti, RemoteCredentialStore credentials,
      @Value("${modulo.remote.allow-private-networks:false}") boolean allowPrivateNetworks) {
    this(cti, credentials, SafeHttpFetcher.create(allowPrivateNetworks)::get);
  }

  CtiEnrichmentService(CtiService cti, RemoteCredentialStore credentials, Fetcher fetcher) {
    this.cti = cti;
    this.credentials = credentials;
    this.fetcher = fetcher;
  }

  /** The providers that apply to a record, each with the time it last ran for this record's value. */
  public Map<String, Object> options(long owner, UUID id) {
    Map<String, Object> object = cti.object(owner, id);
    Observable observable = observable(object);
    List<Map<String, Object>> providers = new ArrayList<>();
    if (observable != null)
      for (String provider : PROVIDERS)
        if (applies(provider, observable)) {
          Map<String, Object> option = new LinkedHashMap<>();
          option.put("provider", provider);
          option.put("query", observable.value());
          Map<String, Object> previous = previous(owner, provider, observable.value());
          option.put("lastRunAt", previous == null ? null : ((JsonNode) previous.get("attributes")).path("performedAt").asText(null));
          providers.add(option);
        }
    return Map.of("observable", observable == null ? Map.of() : Map.of("type", observable.type(), "value", observable.value()),
        "providers", providers);
  }

  public Map<String, Object> enrich(long owner, UUID id, String provider, boolean force) {
    if (!PROVIDERS.contains(provider)) throw bad("CTI_UNKNOWN_PROVIDER");
    Map<String, Object> object = cti.object(owner, id);
    Observable observable = observable(object);
    if (observable == null || !applies(provider, observable)) throw bad("CTI_PROVIDER_NOT_APPLICABLE");
    Map<String, Object> previous = previous(owner, provider, observable.value());
    if (!force && previous != null && "done".equals(previous.get("status"))) {
      String performed = ((JsonNode) previous.get("attributes")).path("performedAt").asText(null);
      if (performed != null && Instant.parse(performed).isAfter(Instant.now().minus(REUSE_WINDOW)))
        return Map.of("reused", true, "enrichmentId", previous.get("id"), "summary",
            ((JsonNode) previous.get("attributes")).path("resultSummary").asText(""), "findings", 0);
    }
    Outcome outcome;
    String status = "done";
    try {
      outcome = switch (provider) {
        case "crt.sh" -> crtSh(observable, text(id.toString()));
        case "urlscan" -> urlscan(observable, text(id.toString()));
        case "passive-dns" -> passiveDns(observable, text(id.toString()));
        default -> blockchain(observable, text(id.toString()));
      };
    } catch (ResponseStatusException failure) {
      status = "failed";
      outcome = new Outcome("Lookup failed: " + failure.getReason(), null, List.of(), List.of());
    }
    String tlp = (String) object.get("tlp");
    ObjectNode attributes = JsonNodeFactory.instance.objectNode();
    attributes.put("provider", provider);
    attributes.put("query", observable.value());
    attributes.put("performedAt", Instant.now().toString());
    attributes.put("resultSummary", outcome.summary().length() > 4000 ? outcome.summary().substring(0, 3999) + "…" : outcome.summary());
    if (outcome.resultUrl() != null) attributes.put("resultUrl", outcome.resultUrl());
    List<CtiService.IngestObject> objects = new ArrayList<>();
    objects.add(new CtiService.IngestObject("enrichment", "enrichment", null, status, tlp, null, null, attributes, null, null, null));
    List<CtiService.IngestRelationship> relationships = new ArrayList<>();
    relationships.add(new CtiService.IngestRelationship(text("enrichment"), text(id.toString()), "enriches", null, null, null, null, null));
    for (var finding : outcome.findings())
      objects.add(new CtiService.IngestObject(finding.ref(), finding.kind(), finding.name(), finding.status(), tlp,
          finding.confidence(), finding.description(), finding.attributes(), finding.labels(), finding.firstSeen(), finding.lastSeen()));
    relationships.addAll(outcome.relationships());
    for (var finding : outcome.findings())
      relationships.add(new CtiService.IngestRelationship(text("enrichment"), text(finding.ref()), "enriches", null, null, null, null, null));
    Map<String, Object> result = cti.ingest(owner, new CtiService.IngestBatch("enrichment:" + provider, objects, relationships, null, null));
    UUID enrichment = null;
    int created = 0;
    for (Object entry : (List<?>) result.get("results")) {
      Map<?, ?> row = (Map<?, ?>) entry;
      if ("enrichment".equals(row.get("ref"))) enrichment = (UUID) row.get("id");
      else if ("created".equals(row.get("action"))) created++;
    }
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("reused", false);
    out.put("status", status);
    out.put("enrichmentId", enrichment);
    out.put("summary", outcome.summary());
    out.put("resultUrl", outcome.resultUrl());
    out.put("findings", outcome.findings().size());
    out.put("created", created);
    return out;
  }

  // ------------------------------------------------------------------ providers

  private Outcome crtSh(Observable observable, JsonNode self) {
    String domain = observable.value();
    String query = URLEncoder.encode("%." + domain, StandardCharsets.UTF_8);
    JsonNode certificates = getJson("https://crt.sh/?q=" + query + "&output=json", Map.of("Accept", "application/json"));
    Set<String> names = new TreeSet<>();
    String first = null;
    String last = null;
    Set<String> issuers = new TreeSet<>();
    for (JsonNode certificate : certificates) {
      for (String name : certificate.path("name_value").asText("").split("\\s+")) {
        String host = name.trim().toLowerCase(Locale.ROOT).replaceFirst("^\\*\\.", "");
        if (!host.isEmpty() && (host.equals(domain) || host.endsWith("." + domain)) && CtiValues.DOMAIN.matcher(host).matches()) names.add(host);
      }
      String notBefore = certificate.path("not_before").asText(null);
      if (notBefore != null) {
        if (first == null || notBefore.compareTo(first) < 0) first = notBefore;
        if (last == null || notBefore.compareTo(last) > 0) last = notBefore;
      }
      String issuer = certificate.path("issuer_name").asText("");
      java.util.regex.Matcher organization = Pattern.compile("O=([^,]+)").matcher(issuer);
      if (organization.find()) issuers.add(organization.group(1).replace("\"", "").trim());
    }
    names.remove(domain);
    List<CtiService.IngestObject> findings = new ArrayList<>();
    List<CtiService.IngestRelationship> links = new ArrayList<>();
    int index = 0;
    for (String host : names) {
      if (findings.size() >= MAX_FINDINGS) break;
      String ref = "host-" + index++;
      findings.add(infra(ref, "domain", host));
      links.add(new CtiService.IngestRelationship(text(ref), self, "related-to", null,
          "Shares certificates with " + domain + " (crt.sh)", null, null, null));
    }
    String summary = certificates.size() + " certificates, " + names.size() + " other hostnames"
        + (first == null ? "" : ", issued " + first.substring(0, Math.min(10, first.length())) + " to " + last.substring(0, Math.min(10, last.length())))
        + (issuers.isEmpty() ? "" : ", issuers: " + String.join(", ", issuers.stream().limit(5).toList()))
        + (names.size() > MAX_FINDINGS ? " (first " + MAX_FINDINGS + " recorded)" : "");
    return new Outcome(summary, "https://crt.sh/?q=" + query, findings, links);
  }

  private Outcome urlscan(Observable observable, JsonNode self) {
    String field = switch (observable.type()) {
      case "ipv4", "ipv6" -> "ip";
      default -> "domain";
    };
    String value = "url".equals(observable.type()) ? java.net.URI.create(observable.value()).getHost() : observable.value();
    if (value == null) throw bad("CTI_PROVIDER_NOT_APPLICABLE");
    String query = field + ":" + value;
    Map<String, String> headers = new HashMap<>(Map.of("Accept", "application/json"));
    credentials.currentValue("urlscanApiKey").ifPresent(key -> headers.put("API-Key", key));
    JsonNode response = getJson("https://urlscan.io/api/v1/search/?size=100&q=" + URLEncoder.encode(query, StandardCharsets.UTF_8), headers);
    JsonNode results = response.path("results");
    Set<String> ips = new TreeSet<>();
    Set<String> domains = new TreeSet<>();
    Set<String> asns = new TreeSet<>();
    Set<String> countries = new TreeSet<>();
    String latest = null;
    for (JsonNode result : results) {
      JsonNode page = result.path("page");
      if (page.hasNonNull("ip")) ips.add(page.get("ip").asText());
      if (page.hasNonNull("domain")) domains.add(page.get("domain").asText().toLowerCase(Locale.ROOT));
      if (page.hasNonNull("asnname")) asns.add(page.path("asn").asText("") + " " + page.get("asnname").asText());
      if (page.hasNonNull("country")) countries.add(page.get("country").asText());
      String time = result.path("task").path("time").asText(null);
      if (time != null && (latest == null || time.compareTo(latest) > 0)) latest = time;
    }
    List<CtiService.IngestObject> findings = new ArrayList<>();
    List<CtiService.IngestRelationship> links = new ArrayList<>();
    if ("domain".equals(field)) {
      int index = 0;
      for (String ip : ips) {
        if (findings.size() >= MAX_FINDINGS || !(CtiValues.IPV4.matcher(ip).matches() || ip.contains(":"))) continue;
        String ref = "ip-" + index++;
        findings.add(infra(ref, "ip", ip));
        links.add(new CtiService.IngestRelationship(self, text(ref), "resolves-to", null, "Observed by urlscan.io", null, null, null));
      }
    } else {
      int index = 0;
      for (String domain : domains) {
        if (findings.size() >= MAX_FINDINGS || !CtiValues.DOMAIN.matcher(domain).matches()) continue;
        String ref = "domain-" + index++;
        findings.add(infra(ref, "domain", domain));
        links.add(new CtiService.IngestRelationship(text(ref), self, "resolves-to", null, "Observed by urlscan.io", null, null, null));
      }
    }
    String summary = results.size() + " scans" + (latest == null ? "" : ", latest " + latest.substring(0, Math.min(10, latest.length())))
        + (ips.isEmpty() ? "" : ", IPs: " + String.join(", ", ips.stream().limit(5).toList()))
        + (asns.isEmpty() ? "" : ", ASNs: " + String.join("; ", asns.stream().limit(3).toList()))
        + (countries.isEmpty() ? "" : ", countries: " + String.join(", ", countries));
    return new Outcome(summary, "https://urlscan.io/search/#" + URLEncoder.encode(query, StandardCharsets.UTF_8), findings, links);
  }

  private Outcome passiveDns(Observable observable, JsonNode self) {
    String value = observable.value();
    JsonNode response = getJson("https://api.mnemonic.no/pdns/v3/" + URLEncoder.encode(value, StandardCharsets.UTF_8) + "?limit=100",
        Map.of("Accept", "application/json"));
    JsonNode data = response.path("data");
    boolean ip = observable.type().startsWith("ipv");
    List<CtiService.IngestObject> findings = new ArrayList<>();
    List<CtiService.IngestRelationship> links = new ArrayList<>();
    Set<String> seen = new HashSet<>();
    long firstSeen = Long.MAX_VALUE;
    long lastSeen = 0;
    int index = 0;
    for (JsonNode record : data) {
      String rrtype = record.path("rrtype").asText("").toLowerCase(Locale.ROOT);
      String query = record.path("query").asText("").toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
      String answer = record.path("answer").asText("").toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
      firstSeen = Math.min(firstSeen, record.path("firstSeenTimestamp").asLong(Long.MAX_VALUE));
      lastSeen = Math.max(lastSeen, record.path("lastSeenTimestamp").asLong(0));
      if (findings.size() >= MAX_FINDINGS) continue;
      String first = record.has("firstSeenTimestamp") ? Instant.ofEpochMilli(record.get("firstSeenTimestamp").asLong()).toString() : null;
      String last = record.has("lastSeenTimestamp") ? Instant.ofEpochMilli(record.get("lastSeenTimestamp").asLong()).toString() : null;
      if (!ip && (rrtype.equals("a") || rrtype.equals("aaaa")) && seen.add(answer)
          && (CtiValues.IPV4.matcher(answer).matches() || answer.contains(":"))) {
        String ref = "pdns-" + index++;
        findings.add(infra(ref, "ip", answer));
        links.add(new CtiService.IngestRelationship(self, text(ref), "resolves-to", null, "Passive DNS (Mnemonic)", null, first, last));
      } else if (!ip && rrtype.equals("cname") && seen.add(answer) && CtiValues.DOMAIN.matcher(answer).matches()) {
        String ref = "pdns-" + index++;
        findings.add(infra(ref, "domain", answer));
        links.add(new CtiService.IngestRelationship(self, text(ref), "resolves-to", null, "CNAME (Mnemonic passive DNS)", null, first, last));
      } else if (ip && seen.add(query) && CtiValues.DOMAIN.matcher(query).matches()) {
        String ref = "pdns-" + index++;
        findings.add(infra(ref, "domain", query));
        links.add(new CtiService.IngestRelationship(text(ref), self, "resolves-to", null, "Passive DNS (Mnemonic)", null, first, last));
      }
    }
    String window = lastSeen == 0 ? "" : ", seen " + Instant.ofEpochMilli(firstSeen).toString().substring(0, 10) + " to "
        + Instant.ofEpochMilli(lastSeen).toString().substring(0, 10);
    String summary = data.size() + " passive DNS records, " + seen.size() + " distinct " + (ip ? "hostnames" : "answers") + window;
    return new Outcome(summary, "https://passivedns.mnemonic.no/search/" + URLEncoder.encode(value, StandardCharsets.UTF_8), findings, links);
  }

  private Outcome blockchain(Observable observable, JsonNode self) {
    String address = observable.value();
    if (TRON.matcher(address).matches()) {
      JsonNode account = getJson("https://apilist.tronscanapi.com/api/accountv2?address=" + address, Map.of("Accept", "application/json"));
      List<String> facts = new ArrayList<>();
      if (account.has("balance")) facts.add("balance " + new java.math.BigDecimal(account.get("balance").asText("0")).movePointLeft(6).stripTrailingZeros().toPlainString() + " TRX");
      if (account.has("totalTransactionCount")) facts.add(account.get("totalTransactionCount").asText() + " transactions");
      if (account.has("date_created")) facts.add("created " + Instant.ofEpochMilli(account.get("date_created").asLong()).toString().substring(0, 10));
      if (account.has("latest_operation_time")) facts.add("last active " + Instant.ofEpochMilli(account.get("latest_operation_time").asLong()).toString().substring(0, 10));
      if (account.path("withPriceTokens").isArray()) facts.add(account.get("withPriceTokens").size() + " tokens held");
      return new Outcome("TRON " + (facts.isEmpty() ? "account found" : String.join(", ", facts)), "https://tronscan.org/#/address/" + address, List.of(), List.of());
    }
    if (BITCOIN.matcher(address).matches()) {
      JsonNode stats = getJson("https://mempool.space/api/address/" + address, Map.of("Accept", "application/json")).path("chain_stats");
      long received = stats.path("funded_txo_sum").asLong();
      long spent = stats.path("spent_txo_sum").asLong();
      return new Outcome("Bitcoin: " + stats.path("tx_count").asLong() + " transactions, received "
          + java.math.BigDecimal.valueOf(received).movePointLeft(8).stripTrailingZeros().toPlainString() + " BTC, balance "
          + java.math.BigDecimal.valueOf(received - spent).movePointLeft(8).stripTrailingZeros().toPlainString() + " BTC",
          "https://mempool.space/address/" + address, List.of(), List.of());
    }
    if (ETHEREUM.matcher(address).matches()) {
      JsonNode account = getJson("https://eth.blockscout.com/api/v2/addresses/" + address, Map.of("Accept", "application/json"));
      List<String> facts = new ArrayList<>();
      if (account.hasNonNull("coin_balance"))
        facts.add("balance " + new java.math.BigDecimal(account.get("coin_balance").asText("0")).movePointLeft(18).stripTrailingZeros().toPlainString() + " ETH");
      if (account.path("is_contract").asBoolean(false)) facts.add("contract");
      if (account.hasNonNull("name")) facts.add("name " + account.get("name").asText());
      if (account.path("has_token_transfers").asBoolean(false)) facts.add("has token transfers");
      return new Outcome("Ethereum " + (facts.isEmpty() ? "address found" : String.join(", ", facts)),
          "https://eth.blockscout.com/address/" + address, List.of(), List.of());
    }
    throw bad("CTI_UNSUPPORTED_CHAIN");
  }

  // ------------------------------------------------------------------ helpers

  private JsonNode getJson(String url, Map<String, String> headers) {
    SafeHttpFetcher.Response response = fetcher.get(url, headers);
    if (response.status() == 429) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "CTI_PROVIDER_RATE_LIMITED");
    if (response.status() == 401 || response.status() == 403) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CTI_PROVIDER_UNAUTHORIZED");
    if (response.status() == 404) return JsonNodeFactory.instance.arrayNode();
    if (response.status() >= 400) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CTI_PROVIDER_ERROR_" + response.status());
    try {
      JsonNode node = json.readTree(response.body());
      return node == null ? JsonNodeFactory.instance.arrayNode() : node;
    } catch (java.io.IOException invalid) {
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "CTI_PROVIDER_INVALID_RESPONSE");
    }
  }

  static Observable observable(Map<String, Object> object) {
    JsonNode a = (JsonNode) object.get("attributes");
    String value = a.path("value").asText("");
    return switch ((String) object.get("kind")) {
      case "infrastructure" -> value.isEmpty() ? null : new Observable(CtiValues.inferType(value), value);
      case "indicator" -> value.isEmpty() ? null : new Observable(a.path("indicatorType").asText("other"), value);
      case "identity" -> "wallet".equals(a.path("identityType").asText()) ? new Observable("wallet", value)
          : "email".equals(a.path("identityType").asText()) ? new Observable("email", value) : null;
      case "malware" -> a.has("sha256") ? new Observable("sha256", a.get("sha256").asText()) : null;
      default -> null;
    };
  }

  static boolean applies(String provider, Observable observable) {
    return switch (provider) {
      case "crt.sh" -> "domain".equals(observable.type());
      case "urlscan" -> Set.of("domain", "ipv4", "ipv6", "url").contains(observable.type());
      case "passive-dns" -> Set.of("domain", "ipv4", "ipv6").contains(observable.type());
      case "blockchain-explorer" -> "wallet".equals(observable.type())
          && (TRON.matcher(observable.value()).matches() || BITCOIN.matcher(observable.value()).matches()
              || ETHEREUM.matcher(observable.value()).matches());
      default -> false;
    };
  }

  private Map<String, Object> previous(long owner, String provider, String query) {
    ObjectNode attributes = JsonNodeFactory.instance.objectNode().put("provider", provider).put("query", query);
    String key = CtiValues.naturalKey(cti.taxonomyKind("enrichment"), null, attributes);
    return cti.findByNaturalKey(owner, "enrichment", key);
  }

  private static CtiService.IngestObject infra(String ref, String kind, String value) {
    ObjectNode attributes = JsonNodeFactory.instance.objectNode().put("infraKind", kind).put("value", value);
    return new CtiService.IngestObject(ref, "infrastructure", null, "unknown", null, null, null, attributes, null, null, null);
  }

  private static JsonNode text(String value) {
    return JsonNodeFactory.instance.textNode(value);
  }
}
