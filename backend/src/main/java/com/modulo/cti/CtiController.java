package com.modulo.cti;

import com.fasterxml.jackson.databind.JsonNode;
import com.modulo.security.AuthenticatedUserService;
import java.util.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** Owner-scoped REST API of the CTI pack. Errors return {@code {"code": "<CTI_REASON>"}}. */
@RestController
@RequestMapping("/api/cti")
@PreAuthorize("isAuthenticated()")
public class CtiController {
  private final CtiService cti;
  private final CtiExportService exports;
  private final CtiCsvImport csv;
  private final CtiEnrichmentService enrichment;
  private final CtiTaxiiService taxii;
  private final AuthenticatedUserService users;

  public CtiController(CtiService cti, CtiExportService exports, CtiCsvImport csv, CtiEnrichmentService enrichment,
      CtiTaxiiService taxii, AuthenticatedUserService users) {
    this.cti = cti;
    this.exports = exports;
    this.csv = csv;
    this.enrichment = enrichment;
    this.taxii = taxii;
    this.users = users;
  }

  public record Enrich(String provider, Boolean force) {}

  public record CsvBody(String csv) {}

  @GetMapping("/taxonomy")
  public Object taxonomy() {
    return cti.taxonomy();
  }

  @GetMapping("/summary")
  public Object summary() {
    return cti.summary(users.requireUserId());
  }

  @GetMapping("/objects")
  public Object list(
      @RequestParam(required = false) String kind,
      @RequestParam(required = false) String view,
      @RequestParam(required = false) String q,
      @RequestParam(required = false) String status,
      @RequestParam(required = false) String tlp,
      @RequestParam(required = false) String label,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "50") int limit) {
    return cti.list(users.requireUserId(), kind, view, q, status, tlp, label, page, limit);
  }

  @PostMapping("/objects")
  public Object create(@RequestBody CtiService.ObjectInput input) {
    return cti.create(users.requireUserId(), input, "manual");
  }

  @GetMapping("/objects/{id}")
  public Object get(@PathVariable UUID id) {
    return cti.detail(users.requireUserId(), id);
  }

  @PutMapping("/objects/{id}")
  public Object update(@PathVariable UUID id, @RequestBody CtiService.ObjectInput input) {
    return cti.update(users.requireUserId(), id, input, "manual");
  }

  @DeleteMapping("/objects/{id}")
  public Map<String, Boolean> delete(@PathVariable UUID id, @RequestParam long revision) {
    cti.delete(users.requireUserId(), id, revision);
    return Map.of("deleted", true);
  }

  @PostMapping("/objects/{id}/merge")
  public Object merge(@PathVariable UUID id, @RequestBody CtiService.Merge body) {
    return cti.merge(users.requireUserId(), id, body.into());
  }

  @PostMapping("/relationships")
  public Object link(@RequestBody CtiService.RelationshipInput input) {
    return cti.link(users.requireUserId(), input, "manual");
  }

  @DeleteMapping("/relationships/{id}")
  public Map<String, Boolean> unlink(@PathVariable UUID id) {
    cti.unlink(users.requireUserId(), id);
    return Map.of("deleted", true);
  }

  /** Idempotent batch upsert for watches, agents and scripts. */
  @PostMapping("/ingest")
  public Object ingest(@RequestBody CtiService.IngestBatch batch) {
    return cti.ingest(users.requireUserId(), batch);
  }

  @GetMapping("/graph")
  public Object graph(
      @RequestParam(required = false) UUID focus,
      @RequestParam(defaultValue = "2") int depth,
      @RequestParam(defaultValue = "300") int limit,
      @RequestParam(defaultValue = "false") boolean workflow) {
    return cti.graph(users.requireUserId(), focus, depth, limit, workflow);
  }

  @PostMapping("/graph/reproject")
  public Object reproject() {
    return cti.reproject(users.requireUserId());
  }

  @GetMapping("/changes")
  public Object changes(
      @RequestParam(required = false) String since,
      @RequestParam(required = false) UUID object,
      @RequestParam(defaultValue = "100") int limit) {
    return cti.changes(users.requireUserId(), since, object, limit);
  }

  @GetMapping("/export/stix")
  public Object stix(
      @RequestParam(defaultValue = "green") String tlp,
      @RequestParam(defaultValue = "false") boolean victims,
      @RequestParam(required = false) List<UUID> scope) {
    return exports.stix(users.requireUserId(), new CtiExportService.Options(tlp, victims, scope == null ? null : new HashSet<>(scope)));
  }

  @GetMapping("/export/misp")
  public Object misp(
      @RequestParam(defaultValue = "green") String tlp,
      @RequestParam(required = false) String info,
      @RequestParam(required = false) List<UUID> scope) {
    return exports.misp(users.requireUserId(), new CtiExportService.Options(tlp, false, scope == null ? null : new HashSet<>(scope)), info);
  }

  @PostMapping("/import/stix")
  public Object importStix(@RequestBody JsonNode bundle) {
    return exports.importStix(users.requireUserId(), bundle);
  }

  @PostMapping("/disclosures/{id}/capsule")
  public Object capsule(@PathVariable UUID id) {
    return exports.capsule(users.requireUserId(), id);
  }

  // ---------------------------------------------------------------- notes and opinions

  @PostMapping("/objects/{id}/notes")
  public Object addNote(@PathVariable UUID id, @RequestBody CtiService.NoteInput input) {
    return cti.addNote(users.requireUserId(), id, input);
  }

  @PutMapping("/notes/{id}")
  public Object updateNote(@PathVariable UUID id, @RequestBody CtiService.NoteInput input) {
    return cti.updateNote(users.requireUserId(), id, input);
  }

  @DeleteMapping("/notes/{id}")
  public Map<String, Boolean> deleteNote(@PathVariable UUID id) {
    cti.deleteNote(users.requireUserId(), id);
    return Map.of("deleted", true);
  }

  // ---------------------------------------------------------------- sightings

  @PostMapping("/objects/{id}/sightings")
  public Object addSighting(@PathVariable UUID id, @RequestBody CtiService.SightingInput input) {
    return cti.addSighting(users.requireUserId(), id, input, "manual");
  }

  @DeleteMapping("/sightings/{id}")
  public Map<String, Boolean> deleteSighting(@PathVariable UUID id) {
    cti.deleteSighting(users.requireUserId(), id);
    return Map.of("deleted", true);
  }

  // ---------------------------------------------------------------- inference, ATT&CK

  @PostMapping("/inference/run")
  public Object reinfer() {
    return cti.reinfer(users.requireUserId());
  }

  @GetMapping("/attack")
  public Object attack() {
    return cti.attackUsage(users.requireUserId());
  }

  // ---------------------------------------------------------------- enrichment connectors

  @GetMapping("/objects/{id}/enrichment")
  public Object enrichmentOptions(@PathVariable UUID id) {
    return enrichment.options(users.requireUserId(), id);
  }

  @PostMapping("/objects/{id}/enrich")
  public Object enrich(@PathVariable UUID id, @RequestBody Enrich body) {
    return enrichment.enrich(users.requireUserId(), id, body.provider(), Boolean.TRUE.equals(body.force()));
  }

  // ---------------------------------------------------------------- CSV

  @PostMapping("/import/csv")
  public Object importCsv(@RequestParam String kind, @RequestParam(defaultValue = "false") boolean dryRun,
      @RequestParam(defaultValue = "false") boolean skipInvalid, @RequestBody CsvBody body) {
    return csv.run(users.requireUserId(), kind, body.csv(), dryRun, skipInvalid);
  }

  @GetMapping(value = "/import/csv/template", produces = "text/csv")
  public String csvTemplate(@RequestParam String kind) {
    return csv.template(kind);
  }

  // ---------------------------------------------------------------- TAXII management

  @GetMapping("/taxii/collections")
  public Object taxiiCollections() {
    return taxii.collections(users.requireUserId());
  }

  @PostMapping("/taxii/collections")
  public Object createTaxiiCollection(@RequestBody CtiTaxiiService.CollectionInput input) {
    return taxii.createCollection(users.requireUserId(), input);
  }

  @PutMapping("/taxii/collections/{id}")
  public Object updateTaxiiCollection(@PathVariable UUID id, @RequestBody CtiTaxiiService.CollectionInput input) {
    return taxii.updateCollection(users.requireUserId(), id, input);
  }

  @DeleteMapping("/taxii/collections/{id}")
  public Map<String, Boolean> deleteTaxiiCollection(@PathVariable UUID id) {
    taxii.deleteCollection(users.requireUserId(), id);
    return Map.of("deleted", true);
  }

  @PostMapping("/taxii/collections/{id}/tokens")
  public Object createTaxiiToken(@PathVariable UUID id, @RequestBody(required = false) CtiTaxiiService.TokenInput input) {
    return taxii.createToken(users.requireUserId(), id, input);
  }

  @DeleteMapping("/taxii/tokens/{id}")
  public Map<String, Boolean> revokeTaxiiToken(@PathVariable UUID id) {
    taxii.revokeToken(users.requireUserId(), id);
    return Map.of("revoked", true);
  }

  @GetMapping("/taxii/feeds")
  public Object taxiiFeeds() {
    return taxii.feeds(users.requireUserId());
  }

  @PostMapping("/taxii/feeds")
  public Object createTaxiiFeed(@RequestBody CtiTaxiiService.FeedInput input) {
    return taxii.createFeed(users.requireUserId(), input);
  }

  @PutMapping("/taxii/feeds/{id}")
  public Object updateTaxiiFeed(@PathVariable UUID id, @RequestBody CtiTaxiiService.FeedInput input) {
    return taxii.updateFeed(users.requireUserId(), id, input);
  }

  @DeleteMapping("/taxii/feeds/{id}")
  public Map<String, Boolean> deleteTaxiiFeed(@PathVariable UUID id) {
    taxii.deleteFeed(users.requireUserId(), id);
    return Map.of("deleted", true);
  }

  @PostMapping("/taxii/feeds/{id}/pull")
  public Object pullTaxiiFeed(@PathVariable UUID id) {
    return taxii.pull(users.requireUserId(), id);
  }

  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<Map<String, String>> failure(ResponseStatusException failure) {
    return ResponseEntity.status(failure.getStatus())
        .body(Map.of("code", Objects.toString(failure.getReason(), "CTI_REQUEST_FAILED")));
  }
}
