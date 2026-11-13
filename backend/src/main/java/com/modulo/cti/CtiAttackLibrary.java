package com.modulo.cti;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import org.springframework.stereotype.Component;

/**
 * MITRE ATT&CK Enterprise technique names and tactics, generated from MITRE's STIX data by
 * {@code scripts/generate-attack-library.py} into {@code shared/cti/attack-enterprise.v1.json}.
 */
@Component
public class CtiAttackLibrary {
  public record Technique(String id, String name, List<String> tactics, String parent) {}

  private final Map<String, Technique> techniques = new LinkedHashMap<>();
  private final List<String> tacticOrder = new ArrayList<>();
  private final String version;

  public CtiAttackLibrary() {
    JsonNode root;
    try (InputStream in = CtiAttackLibrary.class.getResourceAsStream("/cti/attack-enterprise.v1.json")) {
      if (in == null) throw new IllegalStateException("ATT&CK library resource missing");
      root = new ObjectMapper().readTree(in);
    } catch (IOException failure) {
      throw new IllegalStateException("ATT&CK library unreadable", failure);
    }
    version = root.path("attackVersion").asText("");
    root.path("tactics").forEach(tactic -> tacticOrder.add(tactic.path("shortname").asText()));
    root.path("techniques").forEach(t -> {
      List<String> tactics = new ArrayList<>();
      t.path("tactics").forEach(tactic -> tactics.add(tactic.asText()));
      techniques.put(t.path("id").asText(), new Technique(t.path("id").asText(), t.path("name").asText(),
          List.copyOf(tactics), t.path("parent").asText(null)));
    });
  }

  public Optional<Technique> technique(String id) {
    return Optional.ofNullable(id == null ? null : techniques.get(id.toUpperCase(Locale.ROOT)));
  }

  /** "Parent: Sub-technique" for sub-techniques, the plain name otherwise; the id when unknown. */
  public String displayName(String id) {
    return technique(id).map(t -> t.parent() == null ? t.name()
        : technique(t.parent()).map(p -> p.name() + ": " + t.name()).orElse(t.name())).orElse(id);
  }

  public int size() {
    return techniques.size();
  }

  public String version() {
    return version;
  }

  public List<String> tactics() {
    return Collections.unmodifiableList(tacticOrder);
  }
}
