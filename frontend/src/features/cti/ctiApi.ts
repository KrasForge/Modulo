// Client for the owner-scoped CTI knowledge base (`/api/cti`). The taxonomy is the
// same JSON the backend validates against (mirrored from shared/cti by
// scripts/sync-pack-assets.py), so forms and the server can never disagree on fields.

import taxonomyJson from './cti-taxonomy.v1.json';
import { authenticatedRequest } from '../../services/authenticatedRequest';

export type Tlp = 'clear' | 'green' | 'amber' | 'amber+strict' | 'red';
export type CtiKind =
  | 'actor' | 'identity' | 'infrastructure' | 'malware' | 'indicator' | 'campaign' | 'victim'
  | 'lead' | 'watch' | 'enrichment' | 'disclosure';
export type AttributeType = 'text' | 'url' | 'select' | 'boolean' | 'number' | 'date' | 'datetime' | 'list';

export interface AttributeSpec {
  type: AttributeType;
  label: string;
  required?: boolean;
  options?: string[];
  format?: string;
  observable?: boolean;
  private?: boolean;
  readOnly?: boolean;
}

export interface KindSpec {
  plugin: string;
  title: string;
  singular: string;
  group: 'knowledge' | 'workflow';
  stixType?: string;
  naturalKey: string;
  private?: boolean;
  statuses: string[];
  attributes: Record<string, AttributeSpec>;
}

export interface Taxonomy {
  version: 1;
  tlp: Tlp[];
  defaultTlp: Tlp;
  kinds: Record<CtiKind, KindSpec>;
  relationships: Record<string, { from: string[]; to: string[] }>;
}

export const TAXONOMY = taxonomyJson as unknown as Taxonomy;
export const KINDS = Object.keys(TAXONOMY.kinds) as CtiKind[];
export const TLP_LEVELS = TAXONOMY.tlp;

export type AttributeValue = string | number | boolean | string[];

export interface CtiObject {
  id: string;
  kind: CtiKind;
  name: string;
  naturalKey: string;
  status: string;
  tlp: Tlp;
  confidence: number | null;
  description: string;
  attributes: Record<string, AttributeValue>;
  labels: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  source: string;
  revision: number;
  createdAt: string;
  updatedAt: string;
  degree?: number;
}

export interface ObjectHead { id: string; kind: CtiKind; name: string; status: string; tlp: Tlp }

export interface CtiRelationship {
  id: string;
  type: string;
  direction: 'outgoing' | 'incoming';
  sourceId: string;
  targetId: string;
  confidence: number | null;
  description: string;
  tlp: Tlp;
  firstSeen: string | null;
  lastSeen: string | null;
  source: string;
  other: ObjectHead;
}

export interface CtiChange {
  seq: number;
  objectId: string | null;
  kind: CtiKind;
  name: string;
  action: string;
  detail: Record<string, unknown>;
  source: string;
  at: string;
}

export interface CtiDetail extends CtiObject {
  relationships: CtiRelationship[];
  history: CtiChange[];
}

export interface Page<T> { items: T[]; total: number; page: number; limit: number; hasMore: boolean }

export type SavedView =
  | 'live-c2' | 'open-leads' | 'stale-leads' | 'unattributed-identities'
  | 'expiring-indicators' | 'unhealthy-watches' | 'unnotified-victims';

export const SAVED_VIEWS: Record<SavedView, { label: string; kind: CtiKind; description: string }> = {
  'live-c2': { label: 'Live C2', kind: 'infrastructure', description: 'Live C2, blob hosts and dead drops.' },
  'open-leads': { label: 'Open leads', kind: 'lead', description: 'Leads that are not closed, by priority.' },
  'stale-leads': { label: 'Stale leads', kind: 'lead', description: 'Open leads untouched for 14 days.' },
  'unattributed-identities': { label: 'Unattributed identities', kind: 'identity', description: 'Identities with no attribution through any alias chain.' },
  'expiring-indicators': { label: 'Expiring indicators', kind: 'indicator', description: 'Active indicators valid for at most 14 more days.' },
  'unhealthy-watches': { label: 'Unhealthy watches', kind: 'watch', description: 'Watches that are failing or have not reported for 2 days.' },
  'unnotified-victims': { label: 'Unnotified victims', kind: 'victim', description: 'Victims not yet notified.' },
};

export interface Summary {
  counts: Record<CtiKind, number>;
  relationships: number;
  views: Record<SavedView, Page<CtiObject>>;
  recentChanges: { items: CtiChange[]; totals: Record<string, number> };
  graphProjection: 'neo4j' | 'postgres-only';
}

export interface GraphNode { id: string; kind: CtiKind; name: string; status: string; tlp: Tlp; confidence: number | null; depth: number }
export interface GraphEdge { id: string; sourceId: string; targetId: string; type: string; confidence: number | null }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[]; focus: string; projection: string }

export interface ObjectInput {
  kind: CtiKind;
  name?: string;
  status?: string;
  tlp?: Tlp;
  confidence?: number | null;
  description?: string;
  attributes: Record<string, AttributeValue>;
  labels?: string[];
  firstSeen?: string | null;
  lastSeen?: string | null;
  revision?: number;
}

/** A server-classified failure, e.g. `CTI_DUPLICATE_OBJECT`. */
export class CtiError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(describeError(code, status));
  }
}

const MESSAGES: Record<string, string> = {
  CTI_DUPLICATE_OBJECT: 'A record with the same identifying value already exists.',
  CTI_STALE_REVISION: 'Someone else changed this record. Reload it and apply your edit again.',
  CTI_RELATIONSHIP_NOT_ALLOWED: 'That relationship type is not allowed between these kinds.',
  CTI_ATTRIBUTE_REQUIRED: 'Fill in every required field.',
  CTI_NAME_REQUIRED: 'A name is required.',
  CTI_INVALID_DOMAIN: 'That is not a valid domain name.',
  CTI_INVALID_IPV4: 'That is not a valid IPv4 address.',
  CTI_INVALID_URL: 'URLs must start with a scheme such as https://.',
  CTI_INVALID_EMAIL: 'That is not a valid email address.',
  CTI_INVALID_HASH: 'The hash has the wrong length or characters.',
  CTI_INVALID_ATTACK_TECHNIQUE: 'ATT&CK techniques look like T1059 or T1059.007.',
  CTI_DISCLOSURE_EMPTY: 'Link the disclosure to the records it concerns first.',
  CTI_INVALID_STIX_BUNDLE: 'The file is not a STIX 2.1 bundle.',
  CTI_SELF_RELATIONSHIP: 'A record cannot be related to itself.',
};

export function describeError(code: string, status: number): string {
  return MESSAGES[code] ?? (code ? `Request failed: ${code}` : `Request failed (${status}).`);
}

async function request<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const response = await authenticatedRequest(`/api/cti${path}`, init?.body === undefined && !init?.method ? undefined : {
    method: init?.method ?? 'POST',
    headers: init?.body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (!response.ok) {
    let code = '';
    try { code = (await response.json()).code ?? ''; } catch { /* status only */ }
    throw new CtiError(code, response.status);
  }
  return response.json() as Promise<T>;
}

const query = (params: Record<string, string | number | boolean | undefined | null>) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  const text = search.toString();
  return text ? `?${text}` : '';
};

// Responses are shape-checked so a proxy error page or an older server degrades to
// empty data instead of crashing a view.
const record = (value: unknown): Record<string, unknown> => (value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {});
const array = <T>(value: unknown): T[] => (Array.isArray(value) ? value as T[] : []);
function asPage<T>(value: unknown): Page<T> {
  const raw = record(value);
  const items = array<T>(raw.items);
  return { items, total: typeof raw.total === 'number' ? raw.total : items.length, page: Number(raw.page) || 0, limit: Number(raw.limit) || items.length, hasMore: raw.hasMore === true };
}
function asChanges(value: unknown) {
  const raw = record(value);
  return { items: array<CtiChange>(raw.items), since: String(raw.since ?? ''), totals: record(raw.totals) as Record<string, number> };
}
function asSummary(value: unknown): Summary {
  const raw = record(value);
  const views = record(raw.views);
  return {
    counts: record(raw.counts) as Record<CtiKind, number>,
    relationships: Number(raw.relationships) || 0,
    views: Object.fromEntries(Object.keys(SAVED_VIEWS).map(id => [id, asPage<CtiObject>(views[id])])) as Summary['views'],
    recentChanges: asChanges(raw.recentChanges),
    graphProjection: raw.graphProjection === 'neo4j' ? 'neo4j' : 'postgres-only',
  };
}
function asGraph(value: unknown): Graph {
  const raw = record(value);
  return { nodes: array<GraphNode>(raw.nodes), edges: array<GraphEdge>(raw.edges), focus: String(raw.focus ?? ''), projection: String(raw.projection ?? 'postgres-only') };
}
function asDetail(value: unknown): CtiDetail {
  const raw = record(value);
  if (typeof raw.id !== 'string' || typeof raw.kind !== 'string') throw new CtiError('CTI_INVALID_RESPONSE', 200);
  return { ...(raw as unknown as CtiObject), attributes: record(raw.attributes) as CtiObject['attributes'], labels: array<string>(raw.labels),
    relationships: array<CtiRelationship>(raw.relationships), history: array<CtiChange>(raw.history) };
}

export interface ListParams { kind?: CtiKind; view?: SavedView; q?: string; status?: string; tlp?: Tlp; label?: string; page?: number; limit?: number }

export const ctiApi = {
  summary: async () => asSummary(await request<unknown>('/summary')),
  list: async (params: ListParams) => asPage<CtiObject>(await request<unknown>(`/objects${query({ ...params })}`)),
  get: async (id: string) => asDetail(await request<unknown>(`/objects/${encodeURIComponent(id)}`)),
  create: (input: ObjectInput) => request<CtiObject>('/objects', { body: input }),
  update: (id: string, input: ObjectInput) => request<CtiObject>(`/objects/${encodeURIComponent(id)}`, { method: 'PUT', body: input }),
  remove: (id: string, revision: number) => request<{ deleted: boolean }>(`/objects/${encodeURIComponent(id)}${query({ revision })}`, { method: 'DELETE' }),
  merge: (id: string, into: string) => request<CtiObject>(`/objects/${encodeURIComponent(id)}/merge`, { body: { into } }),
  link: (input: { sourceId: string; targetId: string; type: string; confidence?: number | null; description?: string }) =>
    request<{ id: string; created: boolean }>('/relationships', { body: input }),
  unlink: (id: string) => request<{ deleted: boolean }>(`/relationships/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  graph: async (params: { focus?: string; depth?: number; limit?: number; workflow?: boolean }) => asGraph(await request<unknown>(`/graph${query(params)}`)),
  reproject: () => request<{ projected: boolean; projection: string }>('/graph/reproject', { body: {} }),
  changes: async (params: { since?: string; object?: string; limit?: number }) => asChanges(await request<unknown>(`/changes${query(params)}`)),
  exportStix: (tlp: Tlp, victims: boolean) => request<Record<string, unknown>>(`/export/stix${query({ tlp, victims })}`),
  exportMisp: (tlp: Tlp, info?: string) => request<Record<string, unknown>>(`/export/misp${query({ tlp, info })}`),
  importStix: (bundle: unknown) =>
    request<{ created: number; updated: number; unchanged: number; relationshipsCreated: number; skipped: Record<string, number> }>('/import/stix', { body: bundle }),
  ingest: (batch: { source?: string; objects?: Array<Omit<ObjectInput, 'revision'> & { ref?: string }>; relationships?: Array<{ source: unknown; target: unknown; type: string }> }) =>
    request<{ created: number; updated: number; unchanged: number; relationshipsCreated: number; results: Array<{ id: string; kind: CtiKind; action: 'created' | 'updated' | 'unchanged'; ref?: string }> }>('/ingest', { body: batch }),
  capsule: (id: string) => request<{ bundle: Record<string, unknown>; sha256: string; objects: number }>(`/disclosures/${encodeURIComponent(id)}/capsule`, { body: {} }),
};

// ── Pure helpers (unit-tested) ───────────────────────────────────────────────

/** Relationship types allowed from `source` to `target`, mirroring the server rule. */
export function allowedRelationships(source: CtiKind, target: CtiKind): string[] {
  return Object.entries(TAXONOMY.relationships)
    .filter(([, rule]) => (rule.from.includes('*') || rule.from.includes(source)) && (rule.to.includes('*') || rule.to.includes(target)))
    .map(([type]) => type);
}

/** Types with which `kind` can start an edge, for the link picker. */
export function outgoingTypes(kind: CtiKind): string[] {
  return Object.entries(TAXONOMY.relationships)
    .filter(([, rule]) => rule.from.includes('*') || rule.from.includes(kind))
    .map(([type]) => type);
}

export function targetKinds(kind: CtiKind, type: string): CtiKind[] {
  const rule = TAXONOMY.relationships[type];
  if (!rule || !(rule.from.includes('*') || rule.from.includes(kind))) return [];
  return rule.to.includes('*') ? KINDS : (rule.to as CtiKind[]);
}

/** Undo common defanging so pasted IOCs match stored values (`evil[.]com`, `hxxps://`). */
export function refang(value: string): string {
  return value.trim()
    .replace(/\[\s*(?:\.|dot)\s*]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*}/gi, '.')
    .replace(/\[\s*(?:@|at)\s*]|\(\s*(?:@|at)\s*\)/gi, '@')
    .replace(/\[:]/g, ':').replace(/\[:\/\/]/g, '://').replace(/\[\/]/g, '/')
    .replace(/^hxxp(s?)/i, 'http$1').replace(/^fxp/i, 'ftp');
}

/** Defang for display in prose and reports, so values are never clickable by accident. */
export function defang(value: string): string {
  return value.replace(/^http(s?):\/\//i, 'hxxp$1://').replace(/\./g, '[.]').replace(/@/g, '[@]');
}

export const TLP_TONE: Record<Tlp, string> = {
  clear: 'border-border-strong text-muted-foreground',
  green: 'border-transparent bg-success/15 text-success',
  amber: 'border-transparent bg-warning/15 text-warning',
  'amber+strict': 'border-transparent bg-warning/25 text-warning',
  red: 'border-transparent bg-destructive/15 text-destructive',
};

/** Converts a form draft into the attribute map the server expects (drops blanks, splits lists). */
export function cleanAttributes(kind: CtiKind, draft: Record<string, unknown>): Record<string, AttributeValue> {
  const out: Record<string, AttributeValue> = {};
  for (const [key, spec] of Object.entries(TAXONOMY.kinds[kind].attributes)) {
    if (spec.readOnly) continue;
    const value = draft[key];
    if (value === undefined || value === null || value === '') continue;
    if (spec.type === 'list') {
      const items = Array.isArray(value) ? value.map(String) : String(value).split(/[,\n]/);
      const list = [...new Set(items.map(item => item.trim()).filter(Boolean))];
      if (list.length) out[key] = list;
    } else if (spec.type === 'boolean') out[key] = value === true || value === 'true';
    else if (spec.type === 'number') { const n = Number(value); if (Number.isFinite(n)) out[key] = n; }
    else out[key] = spec.observable ? refang(String(value)) : String(value).trim();
  }
  return out;
}

export function relativeAge(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'never';
  const seconds = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (seconds < 90) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 90) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 36) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}
