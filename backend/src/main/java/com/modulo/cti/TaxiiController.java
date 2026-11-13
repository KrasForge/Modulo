package com.modulo.cti;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.*;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * TAXII 2.1 server (OASIS TAXII 2.1, sections 4-5) over the owner's CTI collections. Requests are
 * authenticated by a collection token ({@code Basic <token id:secret>} or {@code Bearer
 * <token id>.<secret>}), not by the Keycloak session, so partners never hold a Modulo login. The
 * security chains exempt {@code /api/taxii2/**}; this controller authenticates every request
 * except discovery itself.
 */
@RestController
@RequestMapping("/api/taxii2")
public class TaxiiController {
  static final MediaType TAXII = MediaType.parseMediaType(CtiTaxiiService.MEDIA_TYPE);
  static final int DEFAULT_LIMIT = 500;
  static final int MAX_LIMIT = 1000;
  static final int MAX_CONTENT_LENGTH = 10 * 1024 * 1024;

  private final CtiTaxiiService taxii;
  private final String publicUrl;
  /** Recent add-objects statuses (TAXII 2.1 section 4.3), bounded per JVM. */
  private final Map<String, Map<String, Object>> statuses =
      Collections.synchronizedMap(new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Map<String, Object>> eldest) {
          return size() > 1000;
        }
      });

  public TaxiiController(CtiTaxiiService taxii, @Value("${modulo.cti.taxii.public-url:}") String publicUrl) {
    this.taxii = taxii;
    this.publicUrl = publicUrl == null ? "" : publicUrl.replaceAll("/+$", "");
  }

  /** Thrown for TAXII error responses; rendered as a TAXII error message. */
  static final class TaxiiError extends RuntimeException {
    final HttpStatus status;

    TaxiiError(HttpStatus status, String title) {
      super(title);
      this.status = status;
    }
  }

  private String base() {
    String root = publicUrl.isEmpty() ? ServletUriComponentsBuilder.fromCurrentContextPath().toUriString().replaceAll("/+$", "") : publicUrl;
    return root + "/api/taxii2/";
  }

  private CtiTaxiiService.Principal principal(HttpServletRequest request) {
    return taxii.authenticate(request.getHeader(HttpHeaders.AUTHORIZATION))
        .orElseThrow(() -> new TaxiiError(HttpStatus.UNAUTHORIZED, "Authentication required"));
  }

  private CtiTaxiiService.Principal scoped(HttpServletRequest request, String id) {
    CtiTaxiiService.Principal principal = principal(request);
    // A token sees exactly one collection; anything else is indistinguishable from absent.
    if (!principal.collection().toString().equalsIgnoreCase(id)) throw new TaxiiError(HttpStatus.NOT_FOUND, "Collection not found");
    return principal;
  }

  private static ResponseEntity<Object> taxii(Object body) {
    return ResponseEntity.ok().contentType(TAXII).body(body);
  }

  @GetMapping("/")
  public ResponseEntity<Object> discovery() {
    return taxii(Map.of("title", "Modulo CTI", "description", "Threat-intelligence collections published from a Modulo workspace.",
        "default", base() + "root/", "api_roots", List.of(base() + "root/")));
  }

  @GetMapping("/root/")
  public ResponseEntity<Object> apiRoot(HttpServletRequest request) {
    principal(request);
    return taxii(Map.of("title", "Modulo CTI", "versions", List.of(CtiTaxiiService.MEDIA_TYPE), "max_content_length", MAX_CONTENT_LENGTH));
  }

  @GetMapping("/root/collections/")
  public ResponseEntity<Object> collections(HttpServletRequest request) {
    return taxii(Map.of("collections", List.of(taxii.collectionResource(principal(request)))));
  }

  @GetMapping("/root/collections/{id}/")
  public ResponseEntity<Object> collection(HttpServletRequest request, @PathVariable String id) {
    return taxii(taxii.collectionResource(scoped(request, id)));
  }

  @GetMapping("/root/collections/{id}/objects/")
  public ResponseEntity<Object> objects(HttpServletRequest request, @PathVariable String id,
      @RequestParam(name = "added_after", required = false) String addedAfter,
      @RequestParam(required = false) Integer limit,
      @RequestParam(required = false) String next,
      @RequestParam(name = "match[id]", required = false) String matchId,
      @RequestParam(name = "match[type]", required = false) String matchType,
      @RequestParam(name = "match[version]", required = false) String matchVersion,
      @RequestParam(name = "match[spec_version]", required = false) String matchSpec) {
    CtiTaxiiService.Principal principal = readable(scoped(request, id));
    List<Map<String, Object>> selected = filter(taxii.collectionObjects(principal), addedAfter, matchId, matchType, matchSpec);
    return page(selected, limit, next, false);
  }

  @GetMapping("/root/collections/{id}/objects/{objectId}/")
  public ResponseEntity<Object> object(HttpServletRequest request, @PathVariable String id, @PathVariable String objectId,
      @RequestParam(name = "added_after", required = false) String addedAfter, @RequestParam(required = false) Integer limit,
      @RequestParam(required = false) String next) {
    CtiTaxiiService.Principal principal = readable(scoped(request, id));
    List<Map<String, Object>> selected = filter(taxii.collectionObjects(principal), addedAfter, objectId, null, null);
    if (selected.isEmpty()) throw new TaxiiError(HttpStatus.NOT_FOUND, "Object not found");
    return page(selected, limit, next, false);
  }

  @GetMapping("/root/collections/{id}/objects/{objectId}/versions/")
  public ResponseEntity<Object> versions(HttpServletRequest request, @PathVariable String id, @PathVariable String objectId) {
    CtiTaxiiService.Principal principal = readable(scoped(request, id));
    List<Map<String, Object>> selected = filter(taxii.collectionObjects(principal), null, objectId, null, null);
    if (selected.isEmpty()) throw new TaxiiError(HttpStatus.NOT_FOUND, "Object not found");
    String version = CtiTaxiiService.dateAdded(selected.get(0));
    return ResponseEntity.ok().contentType(TAXII).header("X-TAXII-Date-Added-First", version).header("X-TAXII-Date-Added-Last", version)
        .body(Map.of("more", false, "versions", List.of(version)));
  }

  @GetMapping("/root/collections/{id}/manifest/")
  public ResponseEntity<Object> manifest(HttpServletRequest request, @PathVariable String id,
      @RequestParam(name = "added_after", required = false) String addedAfter, @RequestParam(required = false) Integer limit,
      @RequestParam(required = false) String next, @RequestParam(name = "match[id]", required = false) String matchId,
      @RequestParam(name = "match[type]", required = false) String matchType) {
    CtiTaxiiService.Principal principal = readable(scoped(request, id));
    return page(filter(taxii.collectionObjects(principal), addedAfter, matchId, matchType, null), limit, next, true);
  }

  @PostMapping("/root/collections/{id}/objects/")
  public ResponseEntity<Object> add(HttpServletRequest request, @PathVariable String id, @RequestBody JsonNode envelope) {
    CtiTaxiiService.Principal principal = scoped(request, id);
    if (!principal.canWrite()) throw new TaxiiError(HttpStatus.FORBIDDEN, "This collection does not accept objects");
    if (request.getContentLengthLong() > MAX_CONTENT_LENGTH) throw new TaxiiError(HttpStatus.PAYLOAD_TOO_LARGE, "Envelope too large");
    String statusId = UUID.randomUUID().toString();
    int total = envelope.path("objects").size();
    Map<String, Object> status = new LinkedHashMap<>();
    status.put("id", statusId);
    status.put("status", "complete");
    status.put("request_timestamp", Instant.now().toString());
    status.put("total_count", total);
    try {
      Map<String, Object> result = taxii.importObjects(principal, envelope);
      int skipped = 0;
      if (result.get("skipped") instanceof Map<?, ?> map) for (Object value : map.values()) skipped += ((Number) value).intValue();
      status.put("success_count", Math.max(0, total - skipped));
      status.put("failure_count", skipped);
      status.put("pending_count", 0);
    } catch (ResponseStatusException rejected) {
      status.put("success_count", 0);
      status.put("failure_count", total);
      status.put("pending_count", 0);
      status.put("failures", List.of(Map.of("id", "envelope", "version", Instant.now().toString(), "message", String.valueOf(rejected.getReason()))));
    }
    statuses.put(principal.collection() + "/" + statusId, status);
    return ResponseEntity.status(HttpStatus.ACCEPTED).contentType(TAXII).body(status);
  }

  @GetMapping("/root/status/{statusId}/")
  public ResponseEntity<Object> status(HttpServletRequest request, @PathVariable String statusId) {
    CtiTaxiiService.Principal principal = principal(request);
    Map<String, Object> status = statuses.get(principal.collection() + "/" + statusId);
    if (status == null) throw new TaxiiError(HttpStatus.NOT_FOUND, "Status not found");
    return taxii(status);
  }

  private static CtiTaxiiService.Principal readable(CtiTaxiiService.Principal principal) {
    if (!principal.canRead()) throw new TaxiiError(HttpStatus.FORBIDDEN, "This collection is write-only");
    return principal;
  }

  static List<Map<String, Object>> filter(List<Map<String, Object>> objects, String addedAfter, String matchId, String matchType, String matchSpec) {
    Set<String> ids = csv(matchId);
    Set<String> types = csv(matchType);
    Set<String> specs = csv(matchSpec);
    String after = addedAfter == null ? null : normalize(addedAfter);
    List<Map<String, Object>> out = new ArrayList<>();
    for (var object : objects) {
      if (after != null && CtiTaxiiService.dateAdded(object).compareTo(after) <= 0) continue;
      if (!ids.isEmpty() && !ids.contains((String) object.get("id"))) continue;
      if (!types.isEmpty() && !types.contains((String) object.get("type"))) continue;
      if (!specs.isEmpty() && !specs.contains(String.valueOf(object.getOrDefault("spec_version", "2.1")))) continue;
      out.add(object);
    }
    return out;
  }

  /** Compares as the export's millisecond UTC format, whatever precision the client sent. */
  static String normalize(String timestamp) {
    try {
      return CtiExportService.stamp(Instant.parse(timestamp).toString());
    } catch (java.time.format.DateTimeParseException invalid) {
      throw new TaxiiError(HttpStatus.BAD_REQUEST, "added_after must be an RFC 3339 timestamp");
    }
  }

  private static Set<String> csv(String value) {
    Set<String> out = new HashSet<>();
    if (value != null) for (String part : value.split(",")) if (!part.isBlank()) out.add(part.trim());
    return out;
  }

  private static ResponseEntity<Object> page(List<Map<String, Object>> selected, Integer limit, String next, boolean manifest) {
    int size = limit == null ? DEFAULT_LIMIT : limit;
    if (size < 1) throw new TaxiiError(HttpStatus.BAD_REQUEST, "limit must be positive");
    size = Math.min(size, MAX_LIMIT);
    int offset = 0;
    if (next != null && !next.isBlank()) {
      try {
        offset = Integer.parseInt(next);
      } catch (NumberFormatException invalid) {
        throw new TaxiiError(HttpStatus.BAD_REQUEST, "Invalid next");
      }
      if (offset < 0 || offset > selected.size()) throw new TaxiiError(HttpStatus.BAD_REQUEST, "Invalid next");
    }
    List<Map<String, Object>> slice = selected.subList(offset, Math.min(selected.size(), offset + size));
    boolean more = offset + slice.size() < selected.size();
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("more", more);
    if (more) body.put("next", String.valueOf(offset + slice.size()));
    if (manifest) {
      List<Map<String, Object>> entries = new ArrayList<>();
      for (var object : slice) {
        String added = CtiTaxiiService.dateAdded(object);
        entries.add(Map.of("id", object.get("id"), "date_added", added, "version", added, "media_type", CtiTaxiiService.STIX_MEDIA_TYPE));
      }
      body.put("objects", entries);
    } else body.put("objects", slice);
    ResponseEntity.BodyBuilder response = ResponseEntity.ok().contentType(TAXII);
    if (!slice.isEmpty()) {
      response.header("X-TAXII-Date-Added-First", CtiTaxiiService.dateAdded(slice.get(0)));
      response.header("X-TAXII-Date-Added-Last", CtiTaxiiService.dateAdded(slice.get(slice.size() - 1)));
    }
    return response.body(body);
  }

  @ExceptionHandler(TaxiiError.class)
  public ResponseEntity<Map<String, Object>> taxiiError(TaxiiError error) {
    ResponseEntity.BodyBuilder response = ResponseEntity.status(error.status).contentType(TAXII);
    if (error.status == HttpStatus.UNAUTHORIZED) response.header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Modulo TAXII\"");
    return response.body(Map.of("title", error.getMessage(), "http_status", String.valueOf(error.status.value())));
  }

  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<Map<String, Object>> failure(ResponseStatusException failure) {
    return ResponseEntity.status(failure.getStatus()).contentType(TAXII)
        .body(Map.of("title", Objects.toString(failure.getReason(), "Request failed"), "http_status", String.valueOf(failure.getStatus().value())));
  }
}
