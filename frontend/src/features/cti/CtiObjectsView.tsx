import { useCallback, useEffect, useMemo, useState, type ComponentType, type ReactNode } from 'react';
import { ArrowLeft, GitMerge, Link2, Network, Pencil, Plus, RefreshCw, Unlink } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Badge, Button, Checkbox, Input, Textarea, cn } from '@/ui';
import {
  Choice,
  ConfirmDelete,
  EmptyPanel,
  Fact,
  FactGrid,
  Field,
  FieldGroup,
  FilterChips,
  ListRow,
  ListRows,
  Panel,
  SearchInput,
  useDeepLink,
  ViewShell,
} from '../workspace/viewkit';
import type { WorkspaceViewProps } from '../workspace/plugins/types';
import {
  SAVED_VIEWS,
  TAXONOMY,
  TLP_LEVELS,
  TLP_TONE,
  allowedRelationships,
  cleanAttributes,
  ctiApi,
  defang,
  relativeAge,
  scoreTone,
  INFERENCE_RULES,
  targetKinds,
  outgoingTypes,
  type AttributeSpec,
  type CtiDetail,
  type CtiKind,
  type CtiObject,
  type ObjectInput,
  type SavedView,
  type Tlp,
} from './ctiApi';
import { KIND_ICONS, attributeSummary, kindView } from './kinds';
import { searchTechniques, techniqueName, techniqueUrl } from './attack';
import { ConnectorsPanel, HistoryPanel, NotesPanel, SightingsPanel } from './CtiDetailPanels';

export interface CtiDetailExtraProps { object: CtiDetail; reload: () => Promise<void> }

export interface CtiObjectsViewProps extends WorkspaceViewProps {
  kind: CtiKind;
  /** Extra panel shown in the detail pane (e.g. the disclosure capsule builder). */
  extraPanel?: ComponentType<CtiDetailExtraProps>;
}

const PAGE = 50;

export function TlpBadge({ tlp }: { tlp: Tlp }) {
  return <Badge className={cn('font-mono uppercase', TLP_TONE[tlp])} title="Traffic Light Protocol">TLP:{tlp}</Badge>;
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const run = useCallback(async (work: () => Promise<string | void>) => {
    setBusy(true); setError(undefined); setNotice(undefined);
    try { const message = await work(); if (message) setNotice(message); return true; }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); return false; }
    finally { setBusy(false); }
  }, []);
  const alert = (error || notice) && (
    <p role={error ? 'alert' : 'status'} className={cn('rounded-md border px-3 py-2 text-[13px]', error ? 'border-destructive/40 text-destructive' : 'border-border text-muted-foreground')}>
      {error ?? notice}
    </p>
  );
  return { busy, run, alert, setError };
}

/** List + detail surface for one CTI kind. Every CTI object plugin renders this. */
export function CtiObjectsView({ kind, extraPanel, ...props }: CtiObjectsViewProps) {
  const spec = TAXONOMY.kinds[kind];
  const Icon = KIND_ICONS[kind];
  const views = (Object.keys(SAVED_VIEWS) as SavedView[]).filter(view => SAVED_VIEWS[view].kind === kind);
  const [q, setQ] = useState('');
  const [status, setStatus] = useState('');
  const [tlp, setTlp] = useState('');
  const [view, setView] = useState<'all' | SavedView>('all');
  const [items, setItems] = useState<CtiObject[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const action = useAction();
  const { run } = action;

  const load = useCallback(async (nextPage = 0) => {
    await run(async () => {
      const result = await ctiApi.list({ kind, q: q || undefined, status: status || undefined, tlp: (tlp || undefined) as Tlp | undefined,
        view: view === 'all' ? undefined : view, page: nextPage, limit: PAGE });
      setItems(previous => nextPage === 0 ? result.items : [...previous, ...result.items]);
      setTotal(result.total);
      setPage(nextPage);
    });
  }, [run, kind, q, status, tlp, view]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(0), q ? 250 : 0);
    return () => window.clearTimeout(timer);
  }, [load, q]);

  useDeepLink('object', id => { setCreating(false); setSelected(id); });
  const showDetail = creating || selected !== null;

  const toolbar = (
    <>
      <SearchInput value={q} onChange={setQ} placeholder={`Search ${spec.title.toLowerCase()}… (defanged values work)`} label={`Search ${spec.title}`} />
      <Choice label="Status" value={status} onChange={setStatus} options={spec.statuses} clearable clearLabel="Any status" placeholder="Any status" layout="stacked" className="w-36" />
      <Choice label="TLP" value={tlp} onChange={setTlp} options={TLP_LEVELS} clearable clearLabel="Any TLP" placeholder="Any TLP" layout="stacked" className="w-32" />
      {views.length > 0 && (
        <FilterChips label="Saved view" value={view} onChange={setView}
          options={[{ value: 'all', label: 'All' }, ...views.map(id => ({ value: id, label: SAVED_VIEWS[id].label }))]} />
      )}
    </>
  );

  return (
    <ViewShell title={spec.title} icon={Icon}
      subtitle={spec.private ? 'Privacy-gated: victims default to TLP:RED and are redacted in every export.' : `${total} ${total === 1 ? spec.singular : `${spec.singular} records`} · STIX ${spec.stixType ?? 'workflow record (never exported)'}`}
      actions={<>
        <Button variant="ghost" size="icon" aria-label="Refresh" onClick={() => void load(0)} disabled={action.busy}><RefreshCw /></Button>
        <Button onClick={() => { setSelected(null); setCreating(true); }}><Plus /> New {spec.singular}</Button>
      </>}
      toolbar={toolbar}>
      {action.alert}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <div className={cn(showDetail && 'phone:hidden')}>
          {items.length === 0 && !action.busy ? (
            <EmptyPanel icon={Icon} title={q || status || tlp || view !== 'all' ? 'No matching records' : `No ${spec.title.toLowerCase()} yet`}
              description={view !== 'all' ? SAVED_VIEWS[view as SavedView].description : 'Create one, or let a watch or the ingest API deliver them.'}
              onReset={q || status || tlp || view !== 'all' ? () => { setQ(''); setStatus(''); setTlp(''); setView('all'); } : undefined} />
          ) : (
            <Panel title={view === 'all' ? 'Records' : SAVED_VIEWS[view as SavedView].label} description={view === 'all' ? undefined : SAVED_VIEWS[view as SavedView].description} bodyClassName="p-0">
              <ListRows>
                {items.map(item => (
                  <ListRow key={item.id} title={item.name} detail={attributeSummary(kind, item.attributes) || item.naturalKey}
                    onOpen={() => { setCreating(false); setSelected(item.id); }}
                    className={cn(selected === item.id && 'bg-muted/30')}
                    meta={<><TlpBadge tlp={item.tlp} />{item.kind === 'indicator' && item.score !== undefined && item.score !== null && <Badge className={cn('font-mono', scoreTone(item.score))} title="Indicator score">{item.score}</Badge>}<Badge variant="outline">{item.status}</Badge>{item.degree ? <span title="Relationships">{item.degree} links</span> : null}<span>{relativeAge(item.updatedAt)}</span></>} />
                ))}
              </ListRows>
              {items.length < total && (
                <div className="p-3"><Button variant="outline" size="sm" disabled={action.busy} onClick={() => void load(page + 1)}>Load more ({total - items.length} left)</Button></div>
              )}
            </Panel>
          )}
        </div>
        <div className={cn(!showDetail && 'phone:hidden')}>
          {creating ? (
            <ObjectEditor kind={kind} onCancel={() => setCreating(false)}
              onSaved={async object => { setCreating(false); setSelected(object.id); await load(0); }} />
          ) : selected ? (
            <ObjectDetail id={selected} kind={kind} extraPanel={extraPanel} onClose={() => setSelected(null)}
              onChanged={() => load(0)} onDeleted={async () => { setSelected(null); await load(0); }} navigateView={props.navigateView} />
          ) : (
            <EmptyPanel icon={Icon} title={`Select a ${spec.singular}`} description="Its relationships, enrichment and history open here." className="phone:hidden" />
          )}
        </div>
      </div>
    </ViewShell>
  );
}

// ── Detail ───────────────────────────────────────────────────────────────────

function formatValue(spec: AttributeSpec, value: unknown): ReactNode {
  if (value === undefined || value === null || value === '') return undefined;
  if (Array.isArray(value) && spec.format === 'attack-technique') {
    return value.length ? <span className="flex flex-wrap gap-1">{value.map(item => (
      <a key={String(item)} href={techniqueUrl(String(item))} target="_blank" rel="noreferrer noopener" title="Open in MITRE ATT&CK">
        <Badge variant="secondary"><span className="font-mono">{String(item)}</span>{techniqueName(String(item)) ? <span className="ml-1">{techniqueName(String(item))}</span> : <span className="ml-1 text-warning">not in ATT&CK library</span>}</Badge>
      </a>
    ))}</span> : undefined;
  }
  if (Array.isArray(value)) return value.length ? <span className="flex flex-wrap gap-1">{value.map(item => <Badge key={String(item)} variant="secondary" className="font-mono">{String(item)}</Badge>)}</span> : undefined;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (spec.type === 'datetime') return `${new Date(String(value)).toLocaleString()} (${relativeAge(String(value))})`;
  if (spec.observable) return <code className="break-all" title="Shown defanged; stored refanged">{defang(String(value))}</code>;
  return String(value);
}

function ObjectDetail({ id, kind, extraPanel: Extra, onClose, onChanged, onDeleted, navigateView }: {
  id: string; kind: CtiKind; extraPanel?: ComponentType<CtiDetailExtraProps>;
  onClose: () => void; onChanged: () => Promise<void>; onDeleted: () => Promise<void>; navigateView: (view: string) => void;
}) {
  const [object, setObject] = useState<CtiDetail>();
  const [editing, setEditing] = useState(false);
  const action = useAction();
  const navigate = useNavigate();
  const { run } = action;
  const reload = useCallback(async () => { await run(async () => setObject(await ctiApi.get(id))); }, [run, id]);
  useEffect(() => { setEditing(false); void reload(); }, [reload]);
  // Opened via a deep link for another kind: hand over to the view that owns it.
  useEffect(() => {
    if (object && object.kind !== kind) navigate(`/app/${kindView(object.kind)}?object=${encodeURIComponent(object.id)}`);
  }, [object, kind, navigate]);

  if (!object) return <Panel title="Loading…">{action.alert ?? <p className="text-[13px] text-muted-foreground">Loading record…</p>}</Panel>;
  const spec = TAXONOMY.kinds[object.kind];
  if (editing) return <ObjectEditor kind={object.kind} existing={object} onCancel={() => setEditing(false)}
    onSaved={async () => { setEditing(false); await reload(); await onChanged(); }} />;

  const open = (target: { id: string; kind: CtiKind }) => navigate(`/app/${kindView(target.kind)}?object=${encodeURIComponent(target.id)}`);
  const groups = new Map<string, typeof object.relationships>();
  for (const rel of object.relationships) {
    const key = `${rel.direction === 'outgoing' ? '' : '← '}${rel.type}`;
    groups.set(key, [...(groups.get(key) ?? []), rel]);
  }

  return (
    <div className="space-y-4">
      <Panel title={<span className="flex min-w-0 items-center gap-2"><Button variant="ghost" size="icon-sm" className="lg:hidden" aria-label="Back to list" onClick={onClose}><ArrowLeft /></Button><span className="truncate">{object.name}</span></span>}
        description={<span className="flex flex-wrap items-center gap-1.5"><TlpBadge tlp={object.tlp} /><Badge variant="outline">{object.status}</Badge>{object.confidence !== null && <Badge variant="secondary">confidence {object.confidence}</Badge>}{object.kind === 'indicator' && object.score !== undefined && object.score !== null && <Badge className={cn('font-mono', scoreTone(object.score))} title={`Decaying score; half-life ${object.halfLifeDays} days`}>score {object.score}</Badge>}{object.labels.map(label => <Badge key={label} variant="secondary">#{label}</Badge>)}</span>}
        actions={<>
          {spec.group === 'knowledge' || object.relationships.length ? <Button variant="ghost" size="icon-sm" aria-label="Open in graph" title="Open in graph" onClick={() => navigateView(`cti-graph?focus=${encodeURIComponent(object.id)}`)}><Network /></Button> : null}
          <Button variant="ghost" size="icon-sm" aria-label="Edit" onClick={() => setEditing(true)}><Pencil /></Button>
          <ConfirmDelete itemName={object.name} itemLabel={spec.singular} consequence="Its relationships are removed too. The change journal keeps a deletion entry."
            onDelete={() => void action.run(async () => { await ctiApi.remove(object.id, object.revision); await onDeleted(); })} />
        </>}>
        {action.alert}
        <FactGrid>
          {Object.entries(spec.attributes).map(([key, attribute]) => (
            <Fact key={key} label={attribute.label} value={formatValue(attribute, object.attributes[key])} wide={attribute.type === 'list' || key === 'value'} />
          ))}
          <Fact label="First seen" value={object.firstSeen ? new Date(object.firstSeen).toLocaleDateString() : undefined} />
          <Fact label="Last seen" value={object.lastSeen ? new Date(object.lastSeen).toLocaleDateString() : undefined} />
          <Fact label="Dedupe key" value={<code className="break-all">{object.naturalKey}</code>} wide />
          <Fact label="Source" value={object.source} />
          <Fact label="Updated" value={`${relativeAge(object.updatedAt)} · revision ${object.revision}`} />
        </FactGrid>
        {object.description && <p className="mt-3 whitespace-pre-wrap text-[13px]">{object.description}</p>}
      </Panel>

      {Extra && <Extra object={object} reload={reload} />}

      <Panel title="Relationships" icon={Link2} description={`${object.relationships.length} typed edges. Click a record to open it.`}>
        {object.relationships.length === 0 ? <p className="text-[13px] text-muted-foreground">No relationships yet.</p> : (
          <div className="space-y-3">
            {[...groups.entries()].map(([type, rels]) => (
              <div key={type}>
                <h4 className="mb-1 font-mono text-xs text-muted-foreground">{type}</h4>
                <ListRows>
                  {rels.map(rel => (
                    <ListRow key={rel.id} title={rel.other.name} leading={(() => { const KindIcon = KIND_ICONS[rel.other.kind]; return <KindIcon className="size-3.5 text-muted-foreground" aria-hidden="true" />; })()}
                      detail={[TAXONOMY.kinds[rel.other.kind].singular, rel.inferredBy ? INFERENCE_RULES[rel.inferredBy] ?? `Inferred (${rel.inferredBy})` : rel.description, rel.confidence !== null ? `confidence ${rel.confidence}` : ''].filter(Boolean).join(' · ')}
                      onOpen={() => open(rel.other)} meta={<>{rel.inferredBy && <Badge variant="outline" title={INFERENCE_RULES[rel.inferredBy]}>inferred</Badge>}<TlpBadge tlp={rel.tlp} /></>}
                      actions={rel.inferredBy ? undefined : <Button variant="ghost" size="icon-sm" aria-label={`Remove ${rel.type} ${rel.other.name}`} onClick={() => void action.run(async () => { await ctiApi.unlink(rel.id); await reload(); })}><Unlink /></Button>} />
                  ))}
                </ListRows>
              </div>
            ))}
          </div>
        )}
        <LinkForm object={object} onLinked={reload} />
      </Panel>

      <SightingsPanel object={object} reload={reload} />
      {spec.group === 'knowledge' && <ConnectorsPanel object={object} reload={reload} />}
      {spec.group === 'knowledge' && <EnrichmentForm object={object} onLogged={reload} />}
      <NotesPanel object={object} reload={reload} />
      <MergePanel object={object} onMerged={async target => { await onChanged(); open({ id: target, kind: object.kind }); }} />

      <HistoryPanel history={object.history} />
    </div>
  );
}

function ObjectSearch({ kinds, exclude, onPick, label }: { kinds: CtiKind[]; exclude: string; onPick: (object: CtiObject) => void; label: string }) {
  const [q, setQ] = useState('');
  const [kind, setKind] = useState<CtiKind>(kinds[0]);
  const [results, setResults] = useState<CtiObject[]>([]);
  useEffect(() => { if (!kinds.includes(kind)) setKind(kinds[0]); }, [kinds, kind]);
  useEffect(() => {
    if (!kind) return;
    let live = true;
    const timer = window.setTimeout(() => {
      void ctiApi.list({ kind, q: q || undefined, limit: 8 }).then(page => { if (live) setResults(page.items.filter(item => item.id !== exclude)); }).catch(() => { if (live) setResults([]); });
    }, 200);
    return () => { live = false; window.clearTimeout(timer); };
  }, [kind, q, exclude]);
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        {kinds.length > 1 && <Choice label="Kind" value={kind} onChange={value => setKind(value as CtiKind)} options={kinds.map(value => ({ value, label: TAXONOMY.kinds[value].singular }))} layout="stacked" className="w-44" />}
        <SearchInput value={q} onChange={setQ} placeholder={`Find a ${TAXONOMY.kinds[kind]?.singular ?? 'record'}…`} label={label} />
      </div>
      <ListRows>
        {results.map(result => <ListRow key={result.id} title={result.name} detail={attributeSummary(result.kind, result.attributes)} onOpen={() => onPick(result)} openLabel={`${label}: ${result.name}`} meta={<TlpBadge tlp={result.tlp} />} />)}
      </ListRows>
    </div>
  );
}

function LinkForm({ object, onLinked }: { object: CtiDetail; onLinked: () => Promise<void> }) {
  const [direction, setDirection] = useState<'outgoing' | 'incoming'>('outgoing');
  const [type, setType] = useState('');
  const [confidence, setConfidence] = useState('');
  const [open, setOpen] = useState(false);
  const action = useAction();
  const types = useMemo(() => {
    if (direction === 'outgoing') return outgoingTypes(object.kind);
    return Object.keys(TAXONOMY.relationships).filter(candidate => (Object.keys(TAXONOMY.kinds) as CtiKind[]).some(kind => allowedRelationships(kind, object.kind).includes(candidate)));
  }, [direction, object.kind]);
  const kinds = useMemo(() => {
    if (!type) return [];
    if (direction === 'outgoing') return targetKinds(object.kind, type).filter(kind => kind !== undefined);
    return (Object.keys(TAXONOMY.kinds) as CtiKind[]).filter(kind => allowedRelationships(kind, object.kind).includes(type));
  }, [direction, object.kind, type]);
  if (!open) return <Button variant="outline" size="sm" className="mt-3" onClick={() => setOpen(true)}><Link2 /> Add relationship</Button>;
  return (
    <FieldGroup legend="Add relationship" className="mt-4">
      <Choice label="Direction" value={direction} onChange={value => { setDirection(value as 'outgoing' | 'incoming'); setType(''); }}
        options={[{ value: 'outgoing', label: `${object.name} → other` }, { value: 'incoming', label: `other → ${object.name}` }]} />
      <Choice label="Type" value={type} onChange={setType} options={types} placeholder="Relationship type" />
      <Field label="Confidence (0–100)"><Input type="number" min={0} max={100} value={confidence} onChange={event => setConfidence(event.target.value)} /></Field>
      {action.alert}
      {type && kinds.length > 0 && (
        <ObjectSearch kinds={kinds} exclude={object.id} label="Link"
          onPick={other => void action.run(async () => {
            const result = await ctiApi.link({ sourceId: direction === 'outgoing' ? object.id : other.id, targetId: direction === 'outgoing' ? other.id : object.id, type,
              confidence: confidence === '' ? null : Number(confidence) });
            await onLinked();
            return result.created ? `Linked ${other.name}.` : 'That relationship already existed; its details were refreshed.';
          })} />
      )}
      <div><Button variant="ghost" size="sm" onClick={() => setOpen(false)}>Done</Button></div>
    </FieldGroup>
  );
}

/** Logs an OSINT lookup against this record. Re-logging the same provider + query updates the existing entry instead of duplicating work. */
function EnrichmentForm({ object, onLogged }: { object: CtiDetail; onLogged: () => Promise<void> }) {
  const providers = TAXONOMY.kinds.enrichment.attributes.provider.options ?? [];
  const value = typeof object.attributes.value === 'string' ? object.attributes.value : typeof object.attributes.sha256 === 'string' ? object.attributes.sha256 : object.name;
  const [provider, setProvider] = useState('');
  const [query, setQuery] = useState(value);
  const [summary, setSummary] = useState('');
  const [url, setUrl] = useState('');
  const action = useAction();
  const prior = object.relationships.filter(rel => rel.type === 'enriches' && rel.direction === 'incoming');
  useEffect(() => { setQuery(value); }, [value]);
  return (
    <Panel title="Enrichment" description={prior.length ? `${prior.length} lookups logged — check them before repeating work.` : 'Log every OSINT lookup here so it is never re-derived.'}>
      {prior.length > 0 && <ul className="mb-3 space-y-0.5 text-[13px]">{prior.map(rel => <li key={rel.id}>{rel.other.name}</li>)}</ul>}
      <div className="grid gap-2 sm:grid-cols-2">
        <Choice label="Provider" value={provider} onChange={setProvider} options={providers} layout="stacked" />
        <Field label="Query" layout="stacked"><Input value={query} onChange={event => setQuery(event.target.value)} /></Field>
        <Field label="Result summary" layout="stacked" className="sm:col-span-2"><Textarea rows={2} value={summary} onChange={event => setSummary(event.target.value)} /></Field>
        <Field label="Result URL" layout="stacked" className="sm:col-span-2"><Input type="url" value={url} onChange={event => setUrl(event.target.value)} placeholder="https://…" /></Field>
      </div>
      {action.alert}
      <Button className="mt-3" size="sm" disabled={!provider || !query.trim() || action.busy} onClick={() => void action.run(async () => {
        const result = await ctiApi.ingest({
          source: 'manual',
          objects: [{ ref: 'e', kind: 'enrichment', status: 'done', tlp: object.tlp, attributes: cleanAttributes('enrichment', { provider, query, resultSummary: summary, resultUrl: url, performedAt: new Date().toISOString() }) }],
          relationships: [{ source: 'e', target: object.id, type: 'enriches' }],
        });
        setSummary(''); setUrl('');
        await onLogged();
        return result.created ? 'Lookup logged.' : 'This provider and query were already logged; the entry was updated.';
      })}>Log lookup</Button>
    </Panel>
  );
}

function MergePanel({ object, onMerged }: { object: CtiDetail; onMerged: (target: string) => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const action = useAction();
  if (!open) return <div><Button variant="ghost" size="sm" onClick={() => setOpen(true)}><GitMerge /> Merge duplicate into another {TAXONOMY.kinds[object.kind].singular}…</Button></div>;
  return (
    <Panel title="Merge duplicate" icon={GitMerge} description={`Folds “${object.name}” into the record you pick: relationships move over, lists are unioned, its name becomes an alias and this record is deleted.`}>
      {action.alert}
      <ObjectSearch kinds={[object.kind]} exclude={object.id} label="Merge into" onPick={target => {
        if (!window.confirm(`Merge “${object.name}” into “${target.name}”? This cannot be undone.`)) return;
        void action.run(async () => { await ctiApi.merge(object.id, target.id); await onMerged(target.id); });
      }} />
      <Button variant="ghost" size="sm" className="mt-2" onClick={() => setOpen(false)}>Cancel</Button>
    </Panel>
  );
}

// ── Editor ───────────────────────────────────────────────────────────────────

type Draft = { name: string; status: string; tlp: Tlp; confidence: string; description: string; labels: string; firstSeen: string; lastSeen: string; attributes: Record<string, unknown> };

const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : '');

export function ObjectEditor({ kind, existing, onCancel, onSaved }: { kind: CtiKind; existing?: CtiObject; onCancel: () => void; onSaved: (object: CtiObject) => Promise<void> }) {
  const spec = TAXONOMY.kinds[kind];
  const [draft, setDraft] = useState<Draft>(() => ({
    name: existing?.name ?? '',
    status: existing?.status ?? spec.statuses[0],
    tlp: existing?.tlp ?? (spec.private ? 'red' : TAXONOMY.defaultTlp),
    confidence: existing?.confidence === null || existing?.confidence === undefined ? '' : String(existing.confidence),
    description: existing?.description ?? '',
    labels: existing?.labels.join(', ') ?? '',
    firstSeen: day(existing?.firstSeen),
    lastSeen: day(existing?.lastSeen),
    attributes: { ...(kind === 'victim' && !existing ? { redacted: true } : {}), ...(existing?.attributes ?? {}) },
  }));
  const action = useAction();
  const set = (patch: Partial<Draft>) => setDraft(current => ({ ...current, ...patch }));
  const setAttribute = (key: string, value: unknown) => setDraft(current => ({ ...current, attributes: { ...current.attributes, [key]: value } }));
  const nameOptional = spec.naturalKey !== 'name' && !spec.naturalKey.includes('name');

  const save = () => action.run(async () => {
    const input: ObjectInput = {
      kind,
      name: draft.name.trim() || undefined,
      status: draft.status,
      tlp: draft.tlp,
      confidence: draft.confidence === '' ? null : Number(draft.confidence),
      description: draft.description,
      labels: draft.labels.split(',').map(label => label.trim()).filter(Boolean),
      firstSeen: draft.firstSeen || null,
      lastSeen: draft.lastSeen || null,
      attributes: cleanAttributes(kind, draft.attributes),
      revision: existing?.revision,
    };
    const saved = existing ? await ctiApi.update(existing.id, input) : await ctiApi.create(input);
    await onSaved(saved);
  });

  return (
    <Panel title={existing ? `Edit ${existing.name}` : `New ${spec.singular}`} actions={<Button variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>}>
      <form className="space-y-4" onSubmit={event => { event.preventDefault(); void save(); }}>
        {spec.private && <p className="rounded-md border border-warning/40 px-3 py-2 text-[13px]">Victim records are privacy-gated. Keep “Redact in every export” on unless the victim agreed to be named; the contact channel is never exported.</p>}
        <FieldGroup legend="Record" columns={2}>
          <Field label={nameOptional ? 'Name (defaults to the value)' : 'Name'}><Input value={draft.name} required={!nameOptional} onChange={event => set({ name: event.target.value })} /></Field>
          <Choice label="Status" value={draft.status} onChange={status => set({ status })} options={spec.statuses} />
          <Choice label="TLP" value={draft.tlp} onChange={tlp => set({ tlp: tlp as Tlp })} options={TLP_LEVELS} hint="Exports only include records at or below the TLP you choose." />
          <Field label="Confidence (0–100)"><Input type="number" min={0} max={100} value={draft.confidence} onChange={event => set({ confidence: event.target.value })} /></Field>
          <Field label="First seen"><Input type="date" value={draft.firstSeen} onChange={event => set({ firstSeen: event.target.value })} /></Field>
          <Field label="Last seen"><Input type="date" value={draft.lastSeen} onChange={event => set({ lastSeen: event.target.value })} /></Field>
        </FieldGroup>
        <FieldGroup legend={`${spec.singular[0].toUpperCase()}${spec.singular.slice(1)} details`} columns={2}>
          {Object.entries(spec.attributes).filter(([, attribute]) => !attribute.readOnly).map(([key, attribute]) => (
            <AttributeInput key={key} name={key} spec={attribute} value={draft.attributes[key]} onChange={value => setAttribute(key, value)} />
          ))}
        </FieldGroup>
        <FieldGroup legend="Notes">
          <Field label="Labels (comma-separated)"><Input value={draft.labels} onChange={event => set({ labels: event.target.value })} placeholder="tron-branch, npm" /></Field>
          <Field label="Description"><Textarea rows={4} value={draft.description} onChange={event => set({ description: event.target.value })} /></Field>
        </FieldGroup>
        {action.alert}
        <div className="flex gap-2"><Button type="submit" disabled={action.busy}>{existing ? 'Save changes' : `Create ${spec.singular}`}</Button><Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button></div>
      </form>
    </Panel>
  );
}

function AttributeInput({ name, spec, value, onChange }: { name: string; spec: AttributeSpec; value: unknown; onChange: (value: unknown) => void }) {
  const label = spec.required ? `${spec.label} *` : spec.label;
  switch (spec.type) {
    case 'select':
      return <Choice label={label} value={value ? String(value) : ''} onChange={onChange} options={spec.options ?? []} clearable={!spec.required} />;
    case 'boolean':
      return <Field label={label}><Checkbox aria-label={spec.label} checked={value === true} onCheckedChange={checked => onChange(checked === true)} /></Field>;
    case 'list':
      if (spec.format === 'attack-technique') return <TechniqueInput label={label} value={value} onChange={onChange} />;
      return <Field label={label} hint="Comma or newline separated" className="sm:col-span-2">
        <Textarea rows={2} value={Array.isArray(value) ? value.join(', ') : value === undefined ? '' : String(value)} onChange={event => onChange(event.target.value)} />
      </Field>;
    case 'date':
      return <Field label={label}><Input type="date" value={value ? String(value).slice(0, 10) : ''} onChange={event => onChange(event.target.value)} /></Field>;
    case 'datetime':
      return <Field label={label}><Input type="datetime-local" value={value ? String(value).slice(0, 16) : ''} onChange={event => onChange(event.target.value ? new Date(event.target.value).toISOString() : '')} /></Field>;
    case 'number':
      return <Field label={label}><Input type="number" value={value === undefined ? '' : String(value)} onChange={event => onChange(event.target.value)} /></Field>;
    default:
      return <Field label={label} hint={spec.observable ? 'Defanged input (evil[.]com, hxxps://) is refanged on save.' : undefined} className={name === 'value' || spec.type === 'url' ? 'sm:col-span-2' : undefined}>
        <Input type={spec.type === 'url' ? 'url' : 'text'} required={spec.required} value={value === undefined ? '' : String(value)} onChange={event => onChange(event.target.value)} />
      </Field>;
  }
}

/** ATT&CK technique list with a name search over the bundled MITRE library. */
function TechniqueInput({ label, value, onChange }: { label: string; value: unknown; onChange: (value: unknown) => void }) {
  const [query, setQuery] = useState('');
  const ids = (Array.isArray(value) ? value.map(String) : String(value ?? '').split(/[,\n]/)).map(item => item.trim().toUpperCase()).filter(Boolean);
  const matches = searchTechniques(query, 8).filter(entry => !ids.includes(entry.id));
  return (
    <Field label={label} hint="Search by ID or name; unknown IDs are kept but flagged." className="sm:col-span-2">
      <div className="space-y-2">
        <div className="flex flex-wrap gap-1">
          {ids.map(id => (
            <Badge key={id} variant="secondary" className="gap-1">
              <span className="font-mono">{id}</span>{techniqueName(id) ?? <span className="text-warning">unknown</span>}
              <button type="button" aria-label={`Remove ${id}`} className="ml-1" onClick={() => onChange(ids.filter(item => item !== id))}>×</button>
            </Badge>
          ))}
        </div>
        <Input value={query} onChange={event => setQuery(event.target.value)} placeholder="T1059, JavaScript, phishing…" aria-label="Search ATT&CK techniques"
          onKeyDown={event => { if (event.key === 'Enter' && /^T\d{4}(\.\d{3})?$/i.test(query.trim())) { event.preventDefault(); onChange([...ids, query.trim().toUpperCase()]); setQuery(''); } }} />
        {matches.length > 0 && (
          <ul className="max-h-48 overflow-y-auto rounded-md border border-border text-[13px]">
            {matches.map(entry => (
              <li key={entry.id}><button type="button" className="w-full px-2 py-1 text-left hover:bg-muted/30" onClick={() => { onChange([...ids, entry.id]); setQuery(''); }}>
                <span className="font-mono">{entry.id}</span> {techniqueName(entry.id)}
              </button></li>
            ))}
          </ul>
        )}
      </div>
    </Field>
  );
}
