import { useCallback, useEffect, useState } from 'react';
import { Activity, BookOpenCheck, LayoutDashboard, Network, RefreshCw } from 'lucide-react';
import { Badge, Button, cn } from '@/ui';
import { EmptyPanel, FilterChips, ListRow, ListRows, Metric, MetricRow, Panel, ViewShell } from '../workspace/viewkit';
import type { WorkspaceViewProps } from '../workspace/plugins/types';
import { SAVED_VIEWS, TAXONOMY, ctiApi, relativeAge, type CtiChange, type CtiKind, type SavedView, type Summary } from './ctiApi';
import { KIND_ICONS, attributeSummary, kindView } from './kinds';
import { CTI_RUNBOOKS } from './runbooks';

const WINDOWS = [
  { value: '1', label: '24 h' },
  { value: '7', label: '7 days' },
  { value: '30', label: '30 days' },
] as const;

const PANELS: SavedView[] = ['live-c2', 'open-leads', 'unattributed-identities', 'stale-leads', 'unhealthy-watches', 'expiring-indicators', 'unnotified-victims'];
const KNOWLEDGE: CtiKind[] = ['actor', 'identity', 'infrastructure', 'malware', 'indicator', 'campaign', 'victim'];

/** CTI overview: counts, the saved analyst queues and the "What changed?" briefing. */
export function CtiDashboardView({ data, navigateView }: WorkspaceViewProps) {
  const [summary, setSummary] = useState<Summary>();
  const [windowDays, setWindowDays] = useState<(typeof WINDOWS)[number]['value']>('7');
  const [changes, setChanges] = useState<{ items: CtiChange[]; totals: Record<string, number> }>();
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setBusy(true); setError(undefined);
    try {
      const since = new Date(Date.now() - Number(windowDays) * 86_400_000).toISOString();
      const [nextSummary, nextChanges] = await Promise.all([ctiApi.summary(), ctiApi.changes({ since, limit: 100 })]);
      setSummary(nextSummary); setChanges(nextChanges);
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  }, [windowDays]);
  useEffect(() => { void load(); }, [load]);

  const open = (kind: CtiKind, id?: string | null) => navigateView(id ? `${kindView(kind)}?object=${encodeURIComponent(id)}` : kindView(kind));
  const installRunbooks = async () => {
    setBusy(true); setNotice(undefined); setError(undefined);
    try {
      const existing = new Set(data.notes.map(note => note.title));
      let created = 0;
      for (const runbook of CTI_RUNBOOKS) {
        if (existing.has(runbook.title)) continue;
        if (await data.createNote(runbook.title, runbook.markdown)) created++;
      }
      setNotice(created ? `Created ${created} runbook notes. Run them from Executable Runbooks.` : 'The CTI runbook notes already exist.');
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };

  const view = (id: SavedView) => summary?.views[id];
  const total = (id: SavedView) => view(id)?.total ?? 0;

  return (
    <ViewShell title="CTI Dashboard" icon={LayoutDashboard} subtitle="Threat-intelligence workbench: live C2, open leads, unattributed identities and what changed."
      actions={<>
        <Button variant="outline" onClick={() => navigateView('cti-graph')}><Network /> Graph</Button>
        <Button variant="ghost" size="icon" aria-label="Refresh" disabled={busy} onClick={() => void load()}><RefreshCw /></Button>
      </>}>
      {(error || notice) && <p role={error ? 'alert' : 'status'} className={cn('mb-4 rounded-md border px-3 py-2 text-[13px]', error ? 'border-destructive/40 text-destructive' : 'border-border text-muted-foreground')}>{error ?? notice}</p>}
      {!summary ? (
        <EmptyPanel icon={LayoutDashboard} title={busy ? 'Loading…' : 'Dashboard unavailable'} description={error ?? 'Sign in to load the CTI knowledge base.'} size="page" />
      ) : (
        <div className="space-y-4">
          <MetricRow>
            <Metric label="Live C2" value={total('live-c2')} tone={total('live-c2') ? 'danger' : 'default'} onOpen={() => open('infrastructure')} />
            <Metric label="Open leads" value={total('open-leads')} detail={`${total('stale-leads')} stale`} tone={total('stale-leads') ? 'warning' : 'default'} onOpen={() => open('lead')} />
            <Metric label="Unattributed identities" value={total('unattributed-identities')} tone={total('unattributed-identities') ? 'warning' : 'success'} onOpen={() => open('identity')} />
            <Metric label="Unhealthy watches" value={total('unhealthy-watches')} tone={total('unhealthy-watches') ? 'danger' : 'success'} onOpen={() => open('watch')} />
          </MetricRow>
          <MetricRow>
            {KNOWLEDGE.map(kind => <Metric key={kind} label={TAXONOMY.kinds[kind].title} value={summary.counts[kind] ?? 0} icon={KIND_ICONS[kind]} onOpen={() => open(kind)} />)}
            <Metric label="Relationships" value={summary.relationships} icon={Network} detail={summary.graphProjection === 'neo4j' ? 'Neo4j projection on' : 'Postgres graph'} onOpen={() => navigateView('cti-graph')} />
          </MetricRow>

          <div className="grid gap-4 xl:grid-cols-2">
            <Panel title="What changed?" icon={Activity}
              description={changes ? Object.entries(changes.totals).map(([action, count]) => `${count} ${action}`).join(' · ') || 'Nothing changed.' : undefined}
              actions={<FilterChips label="Window" value={windowDays} onChange={setWindowDays} options={WINDOWS} />} bodyClassName="p-0">
              {changes && changes.items.length ? (
                <ListRows>
                  {changes.items.slice(0, 40).map(change => {
                    const Icon = KIND_ICONS[change.kind];
                    return <ListRow key={change.seq} leading={<Icon className="size-3.5 text-muted-foreground" aria-hidden="true" />}
                      title={`${change.action} · ${change.name}`}
                      detail={[TAXONOMY.kinds[change.kind]?.singular, typeof change.detail.type === 'string' ? `${change.detail.type} → ${String(change.detail.targetName ?? '')}` : '', Array.isArray(change.detail.fields) ? (change.detail.fields as string[]).join(', ') : '', `via ${change.source}`].filter(Boolean).join(' · ')}
                      meta={relativeAge(change.at)} onOpen={change.action === 'deleted' ? undefined : () => open(change.kind, change.objectId)} />;
                  })}
                </ListRows>
              ) : <p className="p-4 text-[13px] text-muted-foreground">No changes in this window.</p>}
            </Panel>
            {PANELS.map(id => {
              const page = view(id);
              const spec = SAVED_VIEWS[id];
              return (
                <Panel key={id} title={`${spec.label} (${page?.total ?? 0})`} description={spec.description} bodyClassName="p-0"
                  actions={<Button variant="ghost" size="sm" onClick={() => open(spec.kind)}>Open</Button>}>
                  {page && page.items.length ? (
                    <ListRows>
                      {page.items.map(item => <ListRow key={item.id} title={item.name} detail={attributeSummary(item.kind, item.attributes)}
                        meta={<><Badge variant="outline">{item.status}</Badge><span>{relativeAge(item.updatedAt)}</span></>} onOpen={() => open(item.kind, item.id)} />)}
                    </ListRows>
                  ) : <p className="p-4 text-[13px] text-muted-foreground">Nothing here.</p>}
                </Panel>
              );
            })}
            <Panel title="Runbooks" icon={BookOpenCheck} description="Procedures for the recurring loops, as notes Executable Runbooks can run with receipts.">
              <ul className="mb-3 list-disc space-y-0.5 pl-5 text-[13px]">{CTI_RUNBOOKS.map(runbook => <li key={runbook.title}>{runbook.title.replace('CTI runbook: ', '')}</li>)}</ul>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" disabled={busy} onClick={() => void installRunbooks()}>Create runbook notes</Button>
                <Button size="sm" variant="outline" onClick={() => navigateView('executable-runbooks')}>Open Executable Runbooks</Button>
                <Button size="sm" variant="outline" onClick={() => navigateView('cti-exchange')}>STIX / MISP exchange</Button>
              </div>
            </Panel>
          </div>
        </div>
      )}
    </ViewShell>
  );
}
