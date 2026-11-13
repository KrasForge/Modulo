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
| `cti-dashboard` | Dashboard, **Graph**, **ATT&CK**, **STIX / MISP / CSV** and **TAXII** views; installs every CTI plugin | — |

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

### Inference rules

The knowledge base derives relationships from the ones you record, so a fact
stated once applies everywhere it logically should. Three rules run after every
change to relationships (link, unlink, ingest, import, merge, delete):

| Rule | From | Derives |
| --- | --- | --- |
| `alias-attribution` | identities joined by `alias-of`, one of them `attributed-to` an actor or campaign | the same attribution for every identity in the alias chain |
| `rotation-inheritance` | infrastructure joined by `rotation-of`, one of them `attributed-to` an actor or campaign, or `uses`d by an actor, campaign or malware | the same attribution and use for every rotation |
| `indicator-propagation` | an indicator `based-on` an observable that is attributed to or used by an actor or campaign (including through the two rules above) | `indicates` that actor or campaign |

- Only relationships you or an ingest recorded are premises of the first two
  rules, so removing a premise retracts everything derived from it. Retractions
  and derivations are journaled (`inferred`, `retracted`, with the rule).
- An inferred relationship carries the premise's confidence (the lower of the
  two for `indicator-propagation`), the stricter TLP of its endpoints, and a
  dashed line in the graph. It cannot be removed by hand: remove its premise.
- Recording a relationship that already exists as an inferred one promotes it
  to an explicit relationship, which then survives the premise.
- Inferred relationships are exported to STIX with `x_modulo_inferred_by`.
- **Re-run inference** on the dashboard (`POST /api/cti/inference/run`) rebuilds
  them, for example after an upgrade adds a rule.

Because aliases inherit attribution, the **Unattributed identities** queue only
lists identities that no alias chain connects to an actor.

## The analyst loop

**Saved views.** The record lists and the dashboard share eight server-side
queues:

| View | Selects |
| --- | --- |
| `live-c2` | Live infrastructure of kind C2, blob host or dead drop |
| `open-leads` | Leads that are not closed, by priority |
| `stale-leads` | Open leads not updated for 14 days |
| `unattributed-identities` | Identities with no attribution anywhere along their `alias-of` chain (no `attributed-to`/`part-of` out, no `controls`/`uses` in) |
| `expiring-indicators` | Active indicators whose valid-until date is at most 14 days away |
| `decayed-indicators` | Active indicators whose score has decayed below 20 |
| `unhealthy-watches` | Watches marked failing, or active ones that have not reported for 2 days |
| `unnotified-victims` | Victims not marked notified |

**Leads** link with `concerns` to every record they are about, so a lead's detail
page is "everything about lead 153".

**Enrichment.** Every knowledge record has an *Enrichment* panel listing prior
lookups. *Log lookup* records the provider, query, summary and result URL as an
enrichment record linked with `enriches`. The same provider and query are one
record, so logging a repeat updates it rather than duplicating the work. For
providers Modulo can call itself, see [Automatic enrichment](#automatic-enrichment).

**Notes and opinions.** Every record has a *Notes & opinions* panel. A note is
free text; an opinion is one of *strongly disagree* to *strongly agree* with an
optional explanation, as in STIX. Each has its own TLP (default: the record's),
is edited with a revision check, and is journaled. Notes and opinions are
exported as STIX `note` and `opinion` objects referencing their record when both
pass the TLP ceiling, and imported back without duplicates.

**What changed?** Every create, update, link, unlink, merge, delete, inference,
sighting, note and capsule build is appended to a change journal with its source
(`manual`, a watch, the STIX importer, a TAXII feed, a connector). An update
records each changed field with its old and new value (`status: open → closed`,
attribute changes per key such as `priority: P2 → P1`; long text is truncated to
300 characters). The dashboard shows the journal for the last 24 hours, 7 or 30
days, and each record shows its own history.

**Runbooks.** *Create runbook notes* on the dashboard adds four procedure notes
that **Executable Runbooks** can run with receipts: pivot an identity, triage new
C2, prepare a disclosure capsule, and the weekly what-changed review.

## Sightings and indicator scoring

A sighting records that a record was seen: when (first and last time), how many
times, where (a sensor, organization or feed), what was observed, and its
source. Sightings can be recorded on indicators, infrastructure, malware,
identities, actors and campaigns, from the record's *Sightings* panel, the
`sightings` array of an ingest batch, a STIX import, or the MCP. Reporting the
same sighting again (same record, place, source and time window) is a no-op, and
each sighting widens the record's first/last-seen window.

Every indicator has a **score** from 0 to 100, computed whenever it is read:

- start from its confidence (50 when unset);
- add 5 for each sighting in the last 30 days, at most 20;
- halve the result for every half-life since its last activity (latest
  sighting, last seen, or valid-from/creation), by indicator type: IPs 30 days,
  URLs 45, domains and filenames 90, emails 120, wallets 180, hashes and
  detection rules (YARA, Sigma, STIX patterns) 365;
- an indicator that is revoked, expired or past its valid-until date scores 0.

A fresh sighting therefore revives a decayed indicator. The *Decayed indicators*
queue lists active indicators below 20. Scores appear in lists, on the record and
in STIX exports (`x_modulo_score`); a MISP export marks an indicator `to_ids`
only while its score is 20 or more. Sightings are exported as STIX `sighting`
objects (sightings of identities are not, because STIX sightings reference
domain objects and identities export as observables).

## ATT&CK

Actors, campaigns and malware carry ATT&CK technique IDs. The editor searches a
bundled copy of MITRE ATT&CK Enterprise by ID or name, and records show each
technique with its name and a link to MITRE. The **ATT&CK** view draws the
Enterprise matrix in tactic order, shading each technique by how many records
use it or its sub-techniques; filter it to one actor, campaign or malware, or
show the whole matrix. IDs that are not in the bundled library (renamed, revoked
or newer) are kept and flagged.

STIX exports emit each technique as an `attack-pattern` with its MITRE name,
`kill_chain_phases` and external reference, linked by `uses`. Imports read
techniques back from `uses` relationships to attack patterns.

The library is [`shared/cti/attack-enterprise.v1.json`](../../shared/cti/attack-enterprise.v1.json),
generated from MITRE's STIX data. To update it:

```sh
curl -sSLo enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python3 scripts/generate-attack-library.py enterprise-attack.json
python3 scripts/sync-pack-assets.py
```

ATT&CK is © The MITRE Corporation and is reproduced under MITRE's terms of use.

## Automatic enrichment

Infrastructure, indicators, wallet and email identities, and malware samples show
an *Automatic enrichment* panel with the connectors that apply to their value.
*Run* calls the provider from the server, logs the lookup as an enrichment record
(`done` or `failed`, with a summary and a link to the result) and ingests what it
discovered, linked to the record and to the lookup:

| Connector | Applies to | Provider | Discovers |
| --- | --- | --- | --- |
| crt.sh certificates | domains | crt.sh certificate transparency | other hostnames under the domain (`related-to`) |
| urlscan.io | domains, IPs, URLs | urlscan.io search | IPs a domain resolved to, or domains seen on an IP (`resolves-to`) |
| Passive DNS | domains, IPs | Mnemonic passive DNS | A/AAAA and CNAME answers, or names that resolved to the IP (`resolves-to`, with first/last seen) |
| Blockchain explorer | TRON, Bitcoin and Ethereum wallets | TRONSCAN, mempool.space, Blockscout | a summary: balance, transactions, creation and last activity |

- A lookup of the same provider and value within ten minutes returns the logged
  result instead of calling the provider; *Run again* forces a new call. Failed
  lookups are logged and never reused.
- Each lookup records at most 50 discoveries. Discovered records take the
  enriched record's TLP and their source is `enrichment:<provider>`.
- Requests go through the server's SSRF-safe fetcher (public addresses only
  unless `modulo.remote.allow-private-networks` is set), so the deployment must
  allow outbound HTTPS to the providers.
- urlscan.io works without a key at a low rate; store a key as the
  `urlscanApiKey` server credential (`PUT /api/remote/credentials/urlscanApiKey`,
  requires `modulo.remote.credential-key`).

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
- Relationship endpoints, and the `target` of each entry in an optional
  `sightings` array, are a batch `ref`, a record id, or `{"kind", "key"}` where
  `key` is the dedupe key. An unresolvable endpoint fails the whole batch
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
`cti_get`, `cti_ingest`, `cti_link`, `cti_changes`, `cti_summary`, `cti_graph`,
`cti_enrich`, `cti_add_sighting` and `cti_add_note`.
An agent asked "what do we know about X?" searches first and records its findings
through the same idempotent ingest.

## CSV bulk import

**STIX / MISP / CSV → CSV bulk import** imports one kind per file:

- Columns: `name`, `status`, `tlp`, `confidence`, `labels`, `firstSeen`,
  `lastSeen`, `description`, and the kind's attributes by key (for example
  `identityType`, `value`, `platform`). *Download template* gives the header row.
  List cells (labels, list attributes) are separated by `;` or `|`. Booleans
  accept `true/false`, `yes/no`, `1/0`.
- `rel:<type>` columns link each row: each cell names targets as
  `<kind>:<dedupe key>`, for example `rel:attributed-to` = `actor:tronzitveca`
  or `rel:alias-of` = `identity:handle:apollo1030109`. Targets may be rows of the
  same file.
- *Validate* checks every row (values, options, duplicates, relationship rules,
  unresolvable targets) and lists problems by line. *Import* writes nothing while
  any row is invalid, unless *Skip invalid rows* is ticked; valid rows are then
  ingested in one transaction through the same idempotent ingest, so importing
  the same file again changes nothing, and inference runs on the result.
- Limits: 5,000 rows and 5 MiB per file; RFC 4180 quoting; a UTF-8 BOM is
  ignored.

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

## TAXII 2.1

The **TAXII** view publishes collections to partners and subscribes to theirs.

**Publishing (server).** A collection is a TLP-capped view of your knowledge base:
title, TLP ceiling, whether victims are included (always pseudonymized when
redacted), and whether partners may read, add objects, or both. Each partner gets
its own token for one collection, shown once:

- TAXII clients use HTTP Basic with the token ID as username and the secret as
  password, or `Authorization: Bearer <token id>.<secret>`.
- Discovery is `https://<your host>/api/taxii2/`; the API root is
  `/api/taxii2/root/`.
- A token sees only its collection; any other collection ID answers 404. Revoking
  a token or deleting the collection stops it immediately. Only the SHA-256 of
  the secret is stored; *last used* is shown per token.
- `objects/` serves the collection's STIX export (the same TLP and privacy rules
  as a file export) with `added_after`, `limit` (default 500, at most 1,000),
  `next`, `match[id]`, `match[type]` and `match[spec_version]`, and the
  `X-TAXII-Date-Added-First/Last` headers. An object's `date_added` is its STIX
  `modified` time. `manifest/`, `objects/{id}/` and `objects/{id}/versions/`
  are served; only the current version of an object exists.
- Adding objects (`POST objects/`) to a writable collection imports them through
  the idempotent STIX import into your knowledge base and returns a completed
  status resource (`status/{id}/`, kept in memory for the last 1,000 requests).
- The TAXII endpoints are exempt from the Keycloak session and CSRF checks; the
  controller authenticates every request except discovery. Set
  `modulo.cti.taxii.public-url` when the server cannot derive its public URL
  behind a proxy.

**Subscribing (client).** A feed names a partner's API root URL, collection ID,
optional username and password, a default TLP for objects that carry no TLP
marking, and an optional poll interval (at least 15 minutes):

- *Pull* pages through `objects/` from the stored `added_after` cursor (at most
  20 pages of 500 per pull) and imports each page through the idempotent STIX
  import with source `taxii:<feed>`. The cursor advances from the server's
  `X-TAXII-Date-Added-Last`; changing a feed's URL or collection resets it.
- Feeds with an interval are polled by the server every few minutes when due;
  each feed is claimed before polling so several backend instances never pull it
  twice. The last result and time are shown on the feed.
- The password is AES-GCM sealed with `modulo.remote.credential-key` and never
  returned; storing one without that key fails with
  `REMOTE_CREDENTIALS_UNCONFIGURED`. Requests go through the SSRF-safe fetcher.

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
| `POST /objects/{id}/notes`, `PUT/DELETE /notes/{id}` | Notes and opinions (`PUT` needs `revision`) |
| `POST /objects/{id}/sightings`, `DELETE /sightings/{id}` | Sightings |
| `POST /inference/run` | Re-run the inference rules |
| `GET /attack` | Which records use which ATT&CK technique |
| `GET /objects/{id}/enrichment`, `POST /objects/{id}/enrich` | Applicable connectors; run one (`{provider, force}`) |
| `POST /import/csv?kind=&dryRun=&skipInvalid=`, `GET /import/csv/template?kind=` | CSV import (`{csv}`) and template |
| `GET/POST /taxii/collections`, `PUT/DELETE /taxii/collections/{id}` | Published TAXII collections |
| `POST /taxii/collections/{id}/tokens`, `DELETE /taxii/tokens/{id}` | Issue (secret shown once) and revoke partner tokens |
| `GET/POST /taxii/feeds`, `PUT/DELETE /taxii/feeds/{id}`, `POST /taxii/feeds/{id}/pull` | Subscribed feeds |

The TAXII 2.1 endpoints themselves are under `/api/taxii2/` (see
[TAXII 2.1](#taxii-21)).

Storage is the `cti_objects`, `cti_relationships` and `cti_changes` tables
([`V29__Cti_knowledge_base.sql`](../../backend/src/main/resources/db/postgresql/V29__Cti_knowledge_base.sql)),
plus `cti_notes`, `cti_sightings`, `cti_taxii_collections`, `cti_taxii_tokens`
and `cti_taxii_feeds`
([`V30__Cti_inference_sightings_notes_taxii.sql`](../../backend/src/main/resources/db/postgresql/V30__Cti_inference_sightings_notes_taxii.sql)).
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
