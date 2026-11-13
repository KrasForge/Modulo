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
  private final AuthenticatedUserService users;

  public CtiController(CtiService cti, CtiExportService exports, AuthenticatedUserService users) {
    this.cti = cti;
    this.exports = exports;
    this.users = users;
  }

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

  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<Map<String, String>> failure(ResponseStatusException failure) {
    return ResponseEntity.status(failure.getStatus())
        .body(Map.of("code", Objects.toString(failure.getReason(), "CTI_REQUEST_FAILED")));
  }
}
