package com.modulo.cti;

import static com.modulo.cti.CtiTaxonomy.bad;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * CSV bulk import for one CTI kind. Columns are {@code name}, {@code status}, {@code tlp},
 * {@code confidence}, {@code description}, {@code labels}, {@code firstSeen}, {@code lastSeen}, any
 * attribute key of the kind, and {@code rel:<type>} columns whose cells name relationship targets
 * as {@code <kind>:<dedupe key>}. List cells (labels, list attributes, relationship targets) are
 * separated by {@code ;} or {@code |}. Every row is validated first; nothing is written unless
 * every row is valid or {@code skipInvalid} is set, and then all valid rows go in one transaction
 * through the idempotent ingest.
 */
@Service
public class CtiCsvImport {
  static final int MAX_ROWS = 5000;
  static final int MAX_BYTES = 5 * 1024 * 1024;
  static final Set<String> CORE = Set.of("name", "status", "tlp", "confidence", "description", "labels", "firstseen", "lastseen");

  private final CtiService cti;
  private final CtiTaxonomy taxonomy;

  public CtiCsvImport(CtiService cti, CtiTaxonomy taxonomy) {
    this.cti = cti;
    this.taxonomy = taxonomy;
  }

  public record RowError(int row, String column, String code) {}

  public Map<String, Object> run(long owner, String kind, String csv, boolean dryRun, boolean skipInvalid) {
    CtiTaxonomy.Kind spec = taxonomy.kind(kind);
    if (csv == null || csv.isBlank()) throw bad("CTI_CSV_EMPTY");
    if (csv.length() > MAX_BYTES) throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "CTI_CSV_TOO_LARGE");
    List<List<String>> rows = parse(csv.startsWith("﻿") ? csv.substring(1) : csv);
    if (rows.isEmpty()) throw bad("CTI_CSV_EMPTY");
    List<String> header = rows.get(0).stream().map(String::trim).toList();
    if (rows.size() - 1 > MAX_ROWS) throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "CTI_CSV_TOO_MANY_ROWS");
    Map<String, String> attributeKeys = new HashMap<>();
    for (String key : spec.attributes().keySet()) attributeKeys.put(key.toLowerCase(Locale.ROOT), key);
    List<RowError> errors = new ArrayList<>();
    Set<String> seenColumns = new HashSet<>();
    for (String column : header) {
      String lower = column.toLowerCase(Locale.ROOT);
      if (!seenColumns.add(lower)) errors.add(new RowError(1, column, "CTI_CSV_DUPLICATE_COLUMN"));
      else if (lower.startsWith("rel:")) {
        if (!taxonomy.relationshipTypes().contains(column.substring(4))) errors.add(new RowError(1, column, "CTI_UNKNOWN_RELATIONSHIP"));
      } else if (!CORE.contains(lower) && !attributeKeys.containsKey(lower)) errors.add(new RowError(1, column, "CTI_CSV_UNKNOWN_COLUMN"));
    }
    if (!errors.isEmpty()) return report(rows.size() - 1, 0, errors, null);

    List<CtiService.IngestObject> objects = new ArrayList<>();
    List<CtiService.IngestRelationship> relationships = new ArrayList<>();
    Set<String> keysInFile = new HashSet<>();
    List<Object[]> pendingLinks = new ArrayList<>();
    for (int index = 1; index < rows.size(); index++) {
      List<String> cells = rows.get(index);
      int line = index + 1;
      if (cells.stream().allMatch(String::isBlank)) continue;
      if (cells.size() > header.size()) {
        errors.add(new RowError(line, null, "CTI_CSV_TOO_MANY_CELLS"));
        continue;
      }
      Map<String, String> core = new HashMap<>();
      ObjectNode attributes = JsonNodeFactory.instance.objectNode();
      List<String[]> links = new ArrayList<>();
      for (int column = 0; column < header.size(); column++) {
        String value = column < cells.size() ? cells.get(column).trim() : "";
        if (value.isEmpty()) continue;
        String name = header.get(column);
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.startsWith("rel:")) {
          for (String target : split(value)) links.add(new String[] {name.substring(4), target, name});
        } else if (CORE.contains(lower)) core.put(lower, value);
        else {
          String key = attributeKeys.get(lower);
          CtiTaxonomy.Attribute attribute = spec.attributes().get(key);
          if ("list".equals(attribute.type())) {
            ArrayNode list = attributes.putArray(key);
            split(value).forEach(list::add);
          } else if ("boolean".equals(attribute.type())) {
            String normalized = value.toLowerCase(Locale.ROOT);
            if (!Set.of("true", "false", "yes", "no", "1", "0").contains(normalized)) {
              errors.add(new RowError(line, name, "CTI_INVALID_ATTRIBUTE"));
              continue;
            }
            attributes.put(key, Set.of("true", "yes", "1").contains(normalized));
          } else if ("number".equals(attribute.type())) {
            try {
              attributes.put(key, Double.parseDouble(value));
            } catch (NumberFormatException notANumber) {
              errors.add(new RowError(line, name, "CTI_INVALID_ATTRIBUTE"));
            }
          } else attributes.put(key, value);
        }
      }
      Integer confidence = null;
      if (core.containsKey("confidence")) {
        try {
          confidence = Integer.valueOf(core.get("confidence"));
        } catch (NumberFormatException notANumber) {
          errors.add(new RowError(line, "confidence", "CTI_INVALID_CONFIDENCE"));
          continue;
        }
      }
      List<String> labels = core.containsKey("labels") ? split(core.get("labels")) : null;
      CtiService.Candidate candidate;
      try {
        candidate = cti.prepare(kind, core.get("name"), core.get("status"), core.get("tlp"), confidence, core.get("description"),
            attributes, labels, core.get("firstseen"), core.get("lastseen"), null);
      } catch (ResponseStatusException invalid) {
        errors.add(new RowError(line, null, invalid.getReason()));
        continue;
      }
      if (!keysInFile.add(candidate.naturalKey())) {
        errors.add(new RowError(line, null, "CTI_CSV_DUPLICATE_ROW"));
        continue;
      }
      String ref = "row-" + line;
      objects.add(new CtiService.IngestObject(ref, kind, core.get("name"), core.get("status"), core.get("tlp"), confidence,
          core.get("description"), attributes, labels, core.get("firstseen"), core.get("lastseen")));
      for (String[] link : links) pendingLinks.add(new Object[] {line, ref, link[0], link[1], link[2]});
    }
    for (Object[] link : pendingLinks) {
      int line = (int) link[0];
      String type = (String) link[2];
      String target = (String) link[3];
      int colon = target.indexOf(':');
      String targetKind = colon < 0 ? "" : target.substring(0, colon).trim();
      String targetKey = colon < 0 ? "" : CtiValues.normalizeKey(target.substring(colon + 1));
      if (!taxonomy.hasKind(targetKind) || targetKey.isEmpty()) {
        errors.add(new RowError(line, (String) link[4], "CTI_CSV_INVALID_TARGET"));
        continue;
      }
      if (!taxonomy.relationshipAllowed(type, kind, targetKind)) {
        errors.add(new RowError(line, (String) link[4], "CTI_RELATIONSHIP_NOT_ALLOWED"));
        continue;
      }
      boolean inFile = targetKind.equals(kind) && keysInFile.contains(targetKey);
      if (!inFile && !cti.exists(owner, targetKind, targetKey)) {
        errors.add(new RowError(line, (String) link[4], "CTI_UNRESOLVED_REFERENCE"));
        continue;
      }
      ObjectNode reference = JsonNodeFactory.instance.objectNode().put("kind", targetKind).put("key", targetKey);
      relationships.add(new CtiService.IngestRelationship(JsonNodeFactory.instance.textNode((String) link[1]), reference, type,
          null, null, null, null, null));
    }
    // A relationship whose source row is invalid is dropped with it.
    Set<Integer> invalidRows = new HashSet<>();
    errors.forEach(error -> invalidRows.add(error.row()));
    objects.removeIf(object -> invalidRows.contains(Integer.parseInt(object.ref().substring(4))));
    Set<String> remaining = new HashSet<>();
    objects.forEach(object -> remaining.add(object.ref()));
    relationships.removeIf(rel -> !remaining.contains(rel.source().asText()));
    if (dryRun || objects.isEmpty() || (!errors.isEmpty() && !skipInvalid)) return report(rows.size() - 1, objects.size(), errors, null);
    Map<String, Object> result = cti.ingest(owner,
        new CtiService.IngestBatch("csv-import", objects, relationships, null, null), MAX_ROWS);
    return report(rows.size() - 1, objects.size(), errors, result);
  }

  private static Map<String, Object> report(int rows, int valid, List<RowError> errors, Map<String, Object> result) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("rows", rows);
    out.put("valid", valid);
    out.put("errors", errors.size() > 500 ? errors.subList(0, 500) : errors);
    out.put("errorCount", errors.size());
    out.put("imported", result != null);
    if (result != null) {
      Map<String, Object> summary = new LinkedHashMap<>(result);
      summary.remove("results");
      out.put("result", summary);
    }
    return out;
  }

  static List<String> split(String value) {
    List<String> out = new ArrayList<>();
    for (String part : value.split("[;|]")) if (!part.isBlank()) out.add(part.trim());
    return out;
  }

  /** RFC 4180: quoted fields, doubled quotes, CRLF or LF line ends, embedded newlines in quotes. */
  static List<List<String>> parse(String text) {
    List<List<String>> rows = new ArrayList<>();
    List<String> row = new ArrayList<>();
    StringBuilder field = new StringBuilder();
    boolean quoted = false;
    boolean any = false;
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (quoted) {
        if (c == '"') {
          if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
            field.append('"');
            i++;
          } else quoted = false;
        } else field.append(c);
        continue;
      }
      if (c == '"' && field.length() == 0) {
        quoted = true;
        any = true;
      } else if (c == ',') {
        row.add(field.toString());
        field.setLength(0);
        any = true;
      } else if (c == '\n' || c == '\r') {
        if (c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') i++;
        row.add(field.toString());
        field.setLength(0);
        rows.add(row);
        row = new ArrayList<>();
        any = false;
      } else {
        field.append(c);
        any = true;
      }
    }
    if (quoted) throw bad("CTI_CSV_UNTERMINATED_QUOTE");
    if (any || field.length() > 0) {
      row.add(field.toString());
      rows.add(row);
    }
    return rows;
  }

  /** Header row for a kind's template download. */
  public String template(String kind) {
    CtiTaxonomy.Kind spec = taxonomy.kind(kind);
    List<String> columns = new ArrayList<>(List.of("name", "status", "tlp", "confidence", "labels", "firstSeen", "lastSeen", "description"));
    for (var attribute : spec.attributes().values()) if (!attribute.readOnly()) columns.add(attribute.key());
    return String.join(",", columns) + "\n";
  }

}
