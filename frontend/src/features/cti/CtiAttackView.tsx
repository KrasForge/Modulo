import { useEffect, useMemo, useState } from 'react';
import { Grid3x3, RefreshCw } from 'lucide-react';
import { Badge, Button, Checkbox, Label, cn } from '@/ui';
import { Choice, EmptyPanel, ListRow, ListRows, Panel, SearchInput, ViewShell } from '../workspace/viewkit';
import type { WorkspaceViewProps } from '../workspace/plugins/types';
import { TAXONOMY, ctiApi, type ObjectHead } from './ctiApi';
import { ATTACK, matrix, techniqueName, techniqueUrl, type AttackTechnique } from './attack';
import { KIND_ICONS, kindView } from './kinds';

const MATRIX = matrix();

/** ATT&CK Enterprise matrix coloured by how many actors, campaigns and malware use each technique. */
export function CtiAttackView({ navigateView }: WorkspaceViewProps) {
  const [usage, setUsage] = useState<Record<string, ObjectHead[]>>({});
  const [subject, setSubject] = useState('');
  const [usedOnly, setUsedOnly] = useState(true);
  const [q, setQ] = useState('');
  const [selected, setSelected] = useState<AttackTechnique>();
  const [error, setError] = useState<string>();
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let live = true;
    ctiApi.attackUsage().then(next => { if (live) { setUsage(next); setError(undefined); } })
      .catch(reason => { if (live) setError(reason instanceof Error ? reason.message : String(reason)); });
    return () => { live = false; };
  }, [revision]);

  const subjects = useMemo(() => {
    const seen = new Map<string, ObjectHead>();
    for (const users of Object.values(usage)) for (const user of users) seen.set(user.id, user);
    return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
  }, [usage]);

  /** Users of a technique, including its sub-techniques, filtered to the chosen subject. */
  const usersOf = (technique: AttackTechnique & { subs?: AttackTechnique[] }): ObjectHead[] => {
    const ids = [technique.id, ...(technique.subs ?? []).map(sub => sub.id)];
    const all = ids.flatMap(id => usage[id] ?? []);
    const unique = [...new Map(all.map(user => [user.id, user])).values()];
    return subject ? unique.filter(user => user.id === subject) : unique;
  };
  const max = Math.max(1, ...MATRIX.flatMap(column => column.techniques.map(technique => usersOf(technique).length)));
  const unknown = Object.keys(usage).filter(id => !techniqueName(id));
  const query = q.trim().toLowerCase();
  const visible = (technique: AttackTechnique & { subs: AttackTechnique[] }) =>
    (!usedOnly || usersOf(technique).length > 0)
    && (!query || `${technique.id} ${technique.name} ${technique.subs.map(sub => `${sub.id} ${sub.name}`).join(' ')}`.toLowerCase().includes(query));
  const used = Object.keys(usage).filter(id => techniqueName(id)).length;

  return (
    <ViewShell title="ATT&CK Matrix" icon={Grid3x3}
      subtitle={`MITRE ATT&CK Enterprise v${ATTACK.attackVersion}: ${ATTACK.techniques.length} techniques, ${used} used by your actors, campaigns and malware.`}
      actions={<Button variant="ghost" size="icon" aria-label="Refresh" onClick={() => setRevision(value => value + 1)}><RefreshCw /></Button>}
      toolbar={<>
        <SearchInput value={q} onChange={setQ} placeholder="Filter techniques…" label="Filter techniques" />
        <Choice label="Subject" value={subject} onChange={setSubject} clearable clearLabel="All records" placeholder="All records" layout="stacked" className="w-56"
          options={subjects.map(user => ({ value: user.id, label: `${user.name} (${TAXONOMY.kinds[user.kind].singular})` }))} />
        <div className="flex items-center gap-2"><Checkbox id="cti-attack-used" checked={usedOnly} onCheckedChange={checked => setUsedOnly(checked === true)} /><Label htmlFor="cti-attack-used" className="text-[13px]">Used techniques only</Label></div>
      </>}>
      {error && <p role="alert" className="mb-4 text-[13px] text-destructive">{error}</p>}
      {unknown.length > 0 && <p className="mb-4 text-[13px] text-warning">Not in the bundled ATT&CK library (renamed, revoked or newer): {unknown.join(', ')}</p>}
      {usedOnly && used === 0 && !error ? (
        <EmptyPanel icon={Grid3x3} title="No techniques recorded yet" description="Add ATT&CK techniques to actors, campaigns or malware, or untick “Used techniques only” to browse the whole matrix." />
      ) : (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
          <div className="overflow-x-auto pb-2">
            <div className="flex min-w-max gap-2">
              {MATRIX.map(({ tactic, techniques }) => {
                const shown = techniques.filter(visible);
                // With a filter on, empty tactics would only push the used ones off-screen.
                if (shown.length === 0 && (usedOnly || query)) return null;
                return (
                  <section key={tactic.id} className="w-44 shrink-0" aria-label={tactic.name}>
                    <h3 className="mb-1 rounded-md bg-surface-2 px-2 py-1 text-xs font-semibold">{tactic.name}<span className="ml-1 font-normal text-muted-foreground">{shown.length}</span></h3>
                    <ul className="space-y-1">
                      {shown.map(technique => {
                        const count = usersOf(technique).length;
                        return (
                          <li key={technique.id}>
                            <button type="button" onClick={() => setSelected(technique)}
                              className={cn('w-full rounded-md border px-2 py-1 text-left text-xs transition-colors', selected?.id === technique.id ? 'border-ring' : 'border-border',
                                count === 0 && 'text-muted-foreground')}
                              style={count ? { background: `hsl(var(--destructive) / ${0.12 + 0.5 * (count / max)})` } : undefined}
                              title={`${technique.id} ${technique.name}`}>
                              <span className="block font-mono text-[10px] text-muted-foreground">{technique.id}{technique.subs.length ? ` · ${technique.subs.length} sub` : ''}</span>
                              <span className="block">{technique.name}</span>
                              {count > 0 && <span className="block font-medium">{count} {count === 1 ? 'record' : 'records'}</span>}
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </section>
                );
              })}
            </div>
          </div>
          <div>
            {selected ? (
              <Panel title={`${selected.id} ${selected.name}`} description={<a className="underline" href={techniqueUrl(selected.id)} target="_blank" rel="noreferrer noopener">MITRE ATT&CK page</a>}>
                {[selected, ...ATTACK.techniques.filter(entry => entry.parent === selected.id)].map(entry => {
                  const users = (usage[entry.id] ?? []).filter(user => !subject || user.id === subject);
                  if (entry.id !== selected.id && users.length === 0) return null;
                  return (
                    <div key={entry.id} className="mb-3">
                      <h4 className="mb-1 text-xs text-muted-foreground"><span className="font-mono">{entry.id}</span> {techniqueName(entry.id)}</h4>
                      {users.length === 0 ? <p className="text-[13px] text-muted-foreground">No records use this technique.</p> : (
                        <ListRows>
                          {users.map(user => {
                            const Icon = KIND_ICONS[user.kind];
                            return <ListRow key={user.id} leading={<Icon className="size-3.5 text-muted-foreground" aria-hidden="true" />} title={user.name}
                              detail={TAXONOMY.kinds[user.kind].singular} meta={<Badge variant="outline">{user.status}</Badge>}
                              onOpen={() => navigateView(`${kindView(user.kind)}?object=${encodeURIComponent(user.id)}`)} />;
                          })}
                        </ListRows>
                      )}
                    </div>
                  );
                })}
              </Panel>
            ) : <Panel title="Select a technique"><p className="text-[13px] text-muted-foreground">Darker cells are used by more records. Select one to see who uses it and its sub-techniques.</p></Panel>}
          </div>
        </div>
      )}
    </ViewShell>
  );
}
