import { useEffect, useMemo, useState } from 'react';
import { Crosshair, Network, RefreshCw } from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { Badge, Button, Checkbox, Label, cn } from '@/ui';
import { EmptyPanel, FilterChips, ListRow, ListRows, Panel, SearchInput, ViewShell } from '../workspace/viewkit';
import type { WorkspaceViewProps } from '../workspace/plugins/types';
import { KINDS, TAXONOMY, ctiApi, type CtiObject, type Graph, type GraphNode } from './ctiApi';
import { KIND_COLORS, KIND_ICONS, attributeSummary, kindView } from './kinds';
import { forceLayout } from './graphLayout';

const WIDTH = 960;
const HEIGHT = 640;
const DEPTHS = [{ value: '1', label: '1 hop' }, { value: '2', label: '2 hops' }, { value: '3', label: '3 hops' }] as const;

/** The CTI knowledge graph: a focus record and its typed neighbourhood, or the most recent overview. */
export function CtiGraphView({ navigateView }: WorkspaceViewProps) {
  const [params, setParams] = useSearchParams();
  const focus = params.get('focus') ?? '';
  const [depth, setDepth] = useState<(typeof DEPTHS)[number]['value']>('2');
  const [workflow, setWorkflow] = useState(false);
  const [graph, setGraph] = useState<Graph>();
  const [selected, setSelected] = useState<GraphNode>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState('');
  const [results, setResults] = useState<CtiObject[]>([]);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let live = true;
    setBusy(true); setError(undefined);
    ctiApi.graph({ focus: focus || undefined, depth: Number(depth), limit: focus ? 300 : 150, workflow })
      .then(next => { if (live) { setGraph(next); setSelected(next.nodes.find(node => node.id === focus)); } })
      .catch(reason => { if (live) setError(reason instanceof Error ? reason.message : String(reason)); })
      .finally(() => { if (live) setBusy(false); });
    return () => { live = false; };
  }, [focus, depth, workflow, revision]);

  useEffect(() => {
    if (!q.trim()) { setResults([]); return; }
    let live = true;
    const timer = window.setTimeout(() => void ctiApi.list({ q, limit: 8 }).then(page => { if (live) setResults(page.items); }).catch(() => undefined), 200);
    return () => { live = false; window.clearTimeout(timer); };
  }, [q]);

  const positions = useMemo(() => graph ? forceLayout(graph.nodes.map(node => node.id), graph.edges, WIDTH, HEIGHT, { focus: focus || undefined }) : new Map(),
    [graph, focus]);
  const setFocus = (id: string) => { const next = new URLSearchParams(params); if (id) next.set('focus', id); else next.delete('focus'); setParams(next); setQ(''); };
  const kindsShown = graph ? KINDS.filter(kind => graph.nodes.some(node => node.kind === kind)) : [];

  return (
    <ViewShell title="CTI Graph" icon={Network}
      subtitle={graph ? `${graph.nodes.length} records · ${graph.edges.length} relationships · ${graph.projection === 'neo4j' ? 'Neo4j projection active' : 'read from Postgres'}` : 'Typed STIX-style relationships between actors, identities, infrastructure, malware and indicators.'}
      actions={<>
        {focus && <Button variant="outline" onClick={() => setFocus('')}>Overview</Button>}
        <Button variant="ghost" size="icon" aria-label="Refresh" disabled={busy} onClick={() => setRevision(value => value + 1)}><RefreshCw /></Button>
      </>}
      toolbar={<>
        <SearchInput value={q} onChange={setQ} placeholder="Focus on a record…" label="Find a record to focus" />
        <FilterChips label="Depth" value={depth} onChange={setDepth} options={DEPTHS} />
        <div className="flex items-center gap-2"><Checkbox id="cti-graph-workflow" checked={workflow} onCheckedChange={checked => setWorkflow(checked === true)} /><Label htmlFor="cti-graph-workflow" className="text-[13px]">Include leads, watches and enrichment</Label></div>
      </>}>
      {results.length > 0 && (
        <Panel title="Focus on" className="mb-4" bodyClassName="p-0">
          <ListRows>{results.map(result => <ListRow key={result.id} title={result.name} detail={`${TAXONOMY.kinds[result.kind].singular} · ${attributeSummary(result.kind, result.attributes)}`} onOpen={() => setFocus(result.id)} openLabel={`Focus on ${result.name}`} />)}</ListRows>
        </Panel>
      )}
      {error && <p role="alert" className="mb-4 rounded-md border border-destructive/40 px-3 py-2 text-[13px] text-destructive">{error}</p>}
      {graph && graph.nodes.length === 0 ? (
        <EmptyPanel icon={Network} title="The graph is empty" description="Create actors, identities and infrastructure and link them, or ingest a watch's findings." size="page" />
      ) : graph && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_18rem]">
          <div className="overflow-hidden rounded-lg border border-border bg-surface-1">
            <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label="CTI knowledge graph" className="h-auto w-full touch-pan-y">
              <defs>
                <marker id="cti-arrow" viewBox="0 0 10 10" refX="18" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="hsl(var(--muted-foreground))" />
                </marker>
              </defs>
              {graph.edges.map(edge => {
                const a = positions.get(edge.sourceId); const b = positions.get(edge.targetId);
                if (!a || !b) return null;
                const highlighted = selected && (edge.sourceId === selected.id || edge.targetId === selected.id);
                return (
                  <g key={edge.id}>
                    <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="hsl(var(--muted-foreground))" strokeOpacity={highlighted ? 0.9 : 0.35} strokeWidth={highlighted ? 2 : 1} markerEnd="url(#cti-arrow)" />
                    {highlighted && <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} textAnchor="middle" className="fill-muted-foreground font-mono text-[11px]">{edge.type}</text>}
                  </g>
                );
              })}
              {graph.nodes.map(node => {
                const point = positions.get(node.id);
                if (!point) return null;
                const isFocus = node.id === focus;
                return (
                  <g key={node.id} transform={`translate(${point.x},${point.y})`} className="cursor-pointer" role="button" tabIndex={0}
                    aria-label={`${TAXONOMY.kinds[node.kind].singular} ${node.name}`}
                    onClick={() => setSelected(node)} onDoubleClick={() => setFocus(node.id)}
                    onKeyDown={event => { if (event.key === 'Enter') setSelected(node); }}>
                    {(() => {
                      const shape = { fill: KIND_COLORS[node.kind], fillOpacity: node.status === 'dead' || node.status === 'retired' ? 0.35 : 0.9,
                        stroke: selected?.id === node.id ? 'hsl(var(--ring))' : 'hsl(var(--background))', strokeWidth: selected?.id === node.id ? 3 : 1.5 };
                      const r = isFocus ? 12 : 8;
                      // Malware is drawn as a square so it never reads as an actor in themes where their hues are close.
                      return node.kind === 'malware' ? <rect x={-r} y={-r} width={2 * r} height={2 * r} rx={2} {...shape} /> : <circle r={r} {...shape} />;
                    })()}
                    {/* Labels near the right edge grow leftwards so they are never clipped. */}
                    <text x={point.x > WIDTH * 0.72 ? -14 : 14} y={4} textAnchor={point.x > WIDTH * 0.72 ? 'end' : 'start'} className={cn('fill-foreground text-[12px]', isFocus && 'font-semibold')}>{node.name.length > 32 ? `${node.name.slice(0, 31)}…` : node.name}</text>
                  </g>
                );
              })}
            </svg>
          </div>
          <div className="space-y-4">
            {selected ? (
              <Panel title={selected.name} description={<span className="flex flex-wrap gap-1"><Badge variant="secondary">{TAXONOMY.kinds[selected.kind].singular}</Badge><Badge variant="outline">{selected.status}</Badge><Badge variant="outline">TLP:{selected.tlp}</Badge></span>}>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" onClick={() => navigateView(`${kindView(selected.kind)}?object=${encodeURIComponent(selected.id)}`)}>Open record</Button>
                  {selected.id !== focus && <Button size="sm" variant="outline" onClick={() => setFocus(selected.id)}><Crosshair /> Focus here</Button>}
                </div>
                <ul className="mt-3 space-y-1 text-[13px]">
                  {graph.edges.filter(edge => edge.sourceId === selected.id || edge.targetId === selected.id).map(edge => {
                    const other = graph.nodes.find(node => node.id === (edge.sourceId === selected.id ? edge.targetId : edge.sourceId));
                    return other && <li key={edge.id}><span className="font-mono text-xs text-muted-foreground">{edge.sourceId === selected.id ? edge.type : `← ${edge.type}`}</span> <button type="button" className="underline" onClick={() => setSelected(other)}>{other.name}</button></li>;
                  })}
                </ul>
              </Panel>
            ) : <Panel title="Select a node"><p className="text-[13px] text-muted-foreground">Click a node to inspect it; double-click to focus the graph on it.</p></Panel>}
            <Panel title="Legend">
              <ul className="space-y-1 text-[13px]">
                {kindsShown.map(kind => { const Icon = KIND_ICONS[kind]; return <li key={kind} className="flex items-center gap-2"><span className="inline-block size-3 rounded-full" style={{ background: KIND_COLORS[kind] }} /><Icon className="size-3.5 text-muted-foreground" aria-hidden="true" />{TAXONOMY.kinds[kind].title}</li>; })}
              </ul>
            </Panel>
          </div>
        </div>
      )}
    </ViewShell>
  );
}
