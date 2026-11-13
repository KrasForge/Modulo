#!/usr/bin/env python3
"""Reduce MITRE ATT&CK Enterprise (STIX 2.1) to the compact technique library the CTI pack uses.

    curl -sSLo enterprise-attack.json \
      https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python3 scripts/generate-attack-library.py enterprise-attack.json
    python3 scripts/sync-pack-assets.py

Writes shared/cti/attack-enterprise.v1.json: tactics in matrix order and every
non-revoked, non-deprecated technique with its name, tactics and parent.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def main(path):
    objects = json.loads(Path(path).read_text(encoding="utf-8"))["objects"]
    live = [o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    matrix = next(o for o in live if o["type"] == "x-mitre-matrix")
    tactic_by_ref = {o["id"]: o for o in live if o["type"] == "x-mitre-tactic"}
    tactics = [{"id": external_id(tactic_by_ref[ref]), "shortname": tactic_by_ref[ref]["x_mitre_shortname"],
                "name": tactic_by_ref[ref]["name"]} for ref in matrix["tactic_refs"] if ref in tactic_by_ref]
    techniques = []
    for o in live:
        if o["type"] != "attack-pattern":
            continue
        technique = external_id(o)
        if not technique:
            continue
        entry = {"id": technique, "name": o["name"],
                 "tactics": sorted({p["phase_name"] for p in o.get("kill_chain_phases", [])
                                    if p.get("kill_chain_name") == "mitre-attack"})}
        if o.get("x_mitre_is_subtechnique"):
            entry["parent"] = technique.split(".")[0]
        techniques.append(entry)
    techniques.sort(key=lambda t: (t["id"].split(".")[0], t["id"]))
    out = {"version": 1, "source": "MITRE ATT&CK Enterprise", "attackVersion": collection.get("x_mitre_version"),
           "license": "ATT&CK is (c) The MITRE Corporation, reproduced under its terms of use.",
           "tactics": tactics, "techniques": techniques}
    target = ROOT / "shared/cti/attack-enterprise.v1.json"
    target.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"{len(tactics)} tactics, {len(techniques)} techniques -> {target.relative_to(ROOT)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
