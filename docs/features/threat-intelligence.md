# Threat intelligence

The **Threat Intelligence Workbench** pack (`pack-threat-intelligence`) turns
Modulo into a cyber-threat-intelligence (CTI) knowledge base in the spirit of
OpenCTI: STIX 2.1-aligned objects, typed relationships, an analyst loop of leads,
watches, enrichment and disclosures, and STIX/MISP exchange. It exists to stop
re-derivation: every alias, lookup and finding is recorded once, deduplicated, and
one hop away from everything it concerns.

This page is for analysts using the pack and for anyone wiring watches or agents
into it. The pack is listed in the [pack catalog](../reference/pack-catalog.md).

## What it installs

Install **Threat Intelligence Workbench** from **Marketplace → Packs**. Its views
appear under **Work → Threat Intelligence**.

| Plugin | Kind | STIX 2.1 mapping |
| --- | --- | --- |
| `cti-actors` | Threat actors and personas: aliases, attribution, motivation, sophistication, ATT&CK techniques, Audit Core threat references | `threat-actor`, plus `attack-pattern` + `uses` per technique |
| `cti-identities` | Observable identities: email, handle, wallet, account, phone, PGP key, registrant | `email-addr`, `cryptocurrency-wallet`, `user-account` |
| `cti-infrastructure` | C2, blob hosts, dead drops, domains, IPs, URLs, registrars, ASNs, repositories | `infrastructure` + `consists-of` its observable |
| `cti-malware` | Families, samples, loaders, droppers, builders, stealers; sample location and evidence-library record IDs | `malware` (+ `file` sample with SHA-256) |
| `cti-indicators` | Shareable IOCs with validity window, source and detection flag | `indicator` with a generated STIX pattern |
| `cti-campaigns` | Campaigns, intrusion sets, clusters, lure sets; branch and objective | `campaign` or `intrusion-set` |
| `cti-victims` | Victims and exposure (privacy-gated) | `identity` (pseudonymized when redacted) |
| `cti-leads` | Leads with number, priority, next step, outcome | never exported |
| `cti-watches` | Recurring watches and their last run | never exported |
| `cti-enrichment` | Log of every OSINT lookup | never exported |
| `cti-disclosures` | Vendor, registrar and law-enforcement reports and takedown requests | `report` in a capsule |
| `cti-dashboard` | Dashboard, **Graph** and **STIX / MISP** views; installs every CTI plugin | — |

The pack also installs Graph, Timeline, Saved Searches, Tags, Executable Runbooks,
What Changed? and Workspace Capsules. `cti-malware` depends on Sources &
Bibliography (`evidence-library`), where sample artifacts and their provenance live;
malware records only reference them.

The kinds, their fields, the allowed statuses and the relationship rules are one
file, [`shared/cti/cti-taxonomy.v1.json`](../../shared/cti/cti-taxonomy.v1.json).
The backend validates against it and the frontend builds its forms from it.
`python3 scripts/sync-pack-assets.py` mirrors it into
`backend/src/main/resources/cti/` and `frontend/src/features/cti/`; CI runs the
script with `--check`.

## Records

Every record has a kind, a name, a status, a TLP level (`clear`, `green`,
`amber`, `amber+strict`, `red`), an optional confidence (0–100), first/last seen,
labels, a description and kind-specific attributes. Unknown attributes are
rejected, select fields only accept their listed options, ATT&CK techniques must
look like `T1059` or `T1059.007`, and hashes, domains, IPs, URLs and emails are
validated.

**Deduplication.** Each record has a dedupe key built from its identifying fields,
for example `handle:apollo1030109` for an identity, `c2:203.0.113.7` for
infrastructure, `sha256:<hash>` for a sample or the lowercased name for an actor.
Only one record per kind and key exists per account. Values are **refanged** on
the way in (`evil[.]example[.]ink`, `hxxps://`, `name[@]mail[dot]com`), so pasted
and defanged indicators match stored ones. The UI shows observables defanged.

**Edits** carry the record's revision. A stale revision is rejected with
`CTI_STALE_REVISION` instead of overwriting someone else's change.

**Merge** folds a duplicate into another record of the same kind: relationships
are re-pointed, list attributes are unioned, the duplicate's name becomes an alias
and the stricter TLP wins.

## Relationships

Relationships are typed, directed edges. The taxonomy limits which kinds each
type may connect:

| Type | From → to |
| --- | --- |
| `uses` | actor, campaign, malware → malware, infrastructure, identity |
| `attributed-to` | campaign, identity, infrastructure, malware, actor → actor, campaign |
| `alias-of` | identity, actor → identity, actor |
| `communicates-with` | malware, infrastructure → infrastructure |
| `resolves-to`, `rotation-of` | infrastructure → infrastructure |
| `hosts` | infrastructure → malware, infrastructure |
| `drops`, `variant-of` | malware → malware |
| `controls` | actor, identity → infrastructure, identity |
| `targets` | actor, campaign, malware → victim |
| `indicates` | indicator → actor, campaign, malware, infrastructure, identity |
| `based-on` | indicator → infrastructure, malware, identity |
| `part-of` | any knowledge kind → campaign |
| `concerns` | lead, watch, disclosure → anything |
| `enriches` | enrichment → anything |
| `related-to` | anything → anything |

A relationship's TLP defaults to the stricter of its two endpoints. Adding an
edge that already exists refreshes its confidence, description and seen window.

**Graph.** The **Graph** view draws a record's neighbourhood (1–3 hops) or the
most recently changed records. Leads, watches and enrichment are hidden by default
so that a lead which concerns two clusters does not visually merge them; enable
*Include leads, watches and enrichment* to see the analyst loop. Postgres is the
source of truth and the graph is read from it. When Neo4j is configured, every
change is also projected as `(:CtiObject {owner, id})-[:CTI_REL {type}]->` nodes
and edges (best effort, like the note graph); `POST /api/cti/graph/reproject`
rebuilds the projection for your account.

## The analyst loop

**Saved views.** The record lists and the dashboard share seven server-side
queues:

| View | Selects |
| --- | --- |
| `live-c2` | Live infrastructure of kind C2, blob host or dead drop |
| `open-leads` | Leads that are not closed, by priority |
| `stale-leads` | Open leads not updated for 14 days |
| `unattributed-identities` | Identities with no attribution anywhere along their `alias-of` chain (no `attributed-to`/`part-of` out, no `controls`/`uses` in) |
| `expiring-indicators` | Active indicators whose valid-until date is at most 14 days away |
| `unhealthy-watches` | Watches marked failing, or active ones that have not reported for 2 days |
| `unnotified-victims` | Victims not marked notified |

**Leads** link with `concerns` to every record they are about, so a lead's detail
page is "everything about lead 153".

**Enrichment.** Every knowledge record has an *Enrichment* panel listing prior
lookups. *Log lookup* records the provider, query, summary and result URL as an
enrichment record linked with `enriches`. The same provider and query are one
record, so logging a repeat updates it rather than duplicating the work.

**What changed?** Every create, update, link, unlink, merge, delete and capsule
build is appended to a change journal with its source (`manual`, a watch, the
STIX importer). The dashboard shows it for the last 24 hours, 7 or 30 days, and
each record shows its own history.

**Runbooks.** *Create runbook notes* on the dashboard adds four procedure notes
that **Executable Runbooks** can run with receipts: pivot an identity, triage new
C2, prepare a disclosure capsule, and the weekly what-changed review.

## Feeding the graph from watches

Cron watches, scripts and agents post findings to `POST /api/cti/ingest`, an
idempotent batch upsert:

```json
{
  "source": "cron:ct-watch",
  "watch": { "watchType": "certificate-transparency", "target": "*.example.ink", "result": "1 new host" },
  "objects": [
    { "ref": "h", "kind": "infrastructure", "status": "live",
      "attributes": { "infraKind": "blob-host", "value": "cdn7[.]example[.]ink" } }
  ],
  "relationships": [
    { "source": "h", "target": { "kind": "infrastructure", "key": "blob-host:cdn6.example.ink" }, "type": "rotation-of" }
  ]
}
```

- Objects are matched by kind and dedupe key. A new key creates a record; an
  existing one is merged: supplied scalars win, list attributes are unioned, the
  first/last-seen window only widens, the description is replaced only when one
  is given, and **TLP is never lowered**. Lower a TLP by editing the record.
- A batch with nothing new reports every object as `unchanged` and writes nothing.
- Relationship endpoints are a batch `ref`, a record id, or `{"kind", "key"}`
  where `key` is the dedupe key. An unresolvable endpoint fails the whole batch
  with `CTI_UNRESOLVED_REFERENCE`; nothing is written.
- `watch` records the run on the watch with that type and target (created on
  first use): last run time, last result and the running count of new findings.
  The watch is linked with `concerns` to every object in the batch.
- A batch holds at most 1,000 objects and 2,000 relationships. An account holds
  at most 200,000 records.

From a shell or cron job, `tools/modulo_mcp/cti_ingest.py findings.json` (or `-`
for stdin) posts a batch with the same `MODULO_BASE_URL` and
`MODULO_API_TOKEN`/`MODULO_API_TOKEN_FILE` settings as the
[Modulo MCP server](../../tools/modulo_mcp/README.md), including refresh-token
rotation.

**Claude and other agents.** The Modulo MCP server exposes `cti_search`,
`cti_get`, `cti_ingest`, `cti_link`, `cti_changes`, `cti_summary` and `cti_graph`.
An agent asked "what do we know about X?" searches first and records its findings
through the same idempotent ingest.

## Exchange and disclosure

**Export** (`STIX / MISP` view, or `GET /api/cti/export/stix` and
`/api/cti/export/misp`) applies a TLP ceiling, default `green`:

- Only records at or below the ceiling are exported, and a relationship only when
  both ends and the relationship itself are.
- Leads, watches and enrichment are never exported.
- Victims are excluded from STIX unless requested and are never in MISP. A
  redacted victim is exported as `Redacted victim <id>` without description,
  labels or sector. The contact channel is never exported.
- STIX objects carry `object_marking_refs` with the STIX 2.1 TLP marking
  definitions. TLP:CLEAR maps to TLP:WHITE; TLP:AMBER+STRICT has its own
  statement marking in the bundle. Observable ids are deterministic (STIX
  UUIDv5), Modulo records keep their UUIDs (`threat-actor--<uuid>`), and custom
  properties use the `x_modulo_` prefix so a bundle round-trips without loss.
- MISP events carry `tlp:` tags, attribute types such as `domain`, `ip-dst`,
  `url`, `sha256`, `email-src` and `btc`, and a `misp-galaxy:threat-actor` tag per
  actor.

**Import** (`POST /api/cti/import/stix`) maps threat actors, intrusion sets,
campaigns, malware (with `file` samples), indicators (simple patterns are parsed
back into type and value), infrastructure with its observables, standalone
observables and Modulo victims onto records through the same ingest, so importing
the same bundle twice changes nothing. Attack patterns linked by `uses` become the
actor's techniques. TLP 1.0 and the OASIS TLP 2.0 marking definitions are
recognised. Unsupported objects are counted under `skipped`.

**Disclosure capsules.** A disclosure has a recipient, a type and a capsule TLP
ceiling. Link it with `concerns` to the records in scope, then *Build and download
capsule* (`POST /api/cti/disclosures/{id}/capsule`). The capsule is a STIX bundle
with a `report` for the disclosure, the records it concerns and their one-hop
knowledge neighbourhood, filtered by the ceiling and the victim rules above. Its
SHA-256 over canonical JSON is stamped on the disclosure (`capsuleSha256`,
`capsuleAt`) and journaled; these fields cannot be set by hand.

## API

All endpoints are under `/api/cti`, owner-scoped, and return
`{"code": "CTI_<REASON>"}` on failure.

| Endpoint | Purpose |
| --- | --- |
| `GET /taxonomy` | Kinds, attributes, relationship types, TLP levels, saved views |
| `GET /summary` | Counts, saved-view queues and recent changes |
| `GET /objects?kind=&view=&q=&status=&tlp=&label=&page=&limit=` | Search and list |
| `POST /objects`, `GET/PUT/DELETE /objects/{id}` | Create, detail (with relationships and history), update with `revision`, delete with `?revision=` |
| `POST /objects/{id}/merge` | `{into}`: fold this record into another |
| `POST /relationships`, `DELETE /relationships/{id}` | Link and unlink |
| `POST /ingest` | Idempotent batch upsert for watches and agents |
| `GET /graph?focus=&depth=&limit=&workflow=` | Neighbourhood or overview |
| `POST /graph/reproject` | Rebuild the Neo4j projection |
| `GET /changes?since=&object=&limit=` | Change journal |
| `GET /export/stix?tlp=&victims=&scope=`, `GET /export/misp?tlp=&info=&scope=` | Exports |
| `POST /import/stix` | Import a STIX 2.1 bundle |
| `POST /disclosures/{id}/capsule` | Build a disclosure capsule |

Storage is the `cti_objects`, `cti_relationships` and `cti_changes` tables
([`V29__Cti_knowledge_base.sql`](../../backend/src/main/resources/db/postgresql/V29__Cti_knowledge_base.sql)).
The implementation is in
[`backend/src/main/java/com/modulo/cti/`](../../backend/src/main/java/com/modulo/cti/)
and [`frontend/src/features/cti/`](../../frontend/src/features/cti/).

## Migrating existing notes

Move an existing cluster in the order that removes re-derivation first:

1. Actors and identities, with `alias-of` and `attributed-to` edges.
2. Infrastructure and indicators, then point the watches at `/api/cti/ingest`.
3. Leads and campaigns, each lead linked with `concerns`.
4. Malware with evidence-library references, victims, enrichment history.
5. Export to STIX or MISP once the graph is complete.

A migration is a single ingest batch per step: write the records with batch
`ref`s and the edges between them, and re-run the batch freely while refining it.
