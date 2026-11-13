import { useEffect, useState } from 'react';
import { Eye, History, MessageSquareText, Pencil, Plug, Trash2 } from 'lucide-react';
import { Badge, Button, Input, Textarea, cn } from '@/ui';
import { Choice, Field, LinkOut, Panel } from '../workspace/viewkit';
import {
  OPINIONS,
  SIGHTABLE,
  TLP_LEVELS,
  TLP_TONE,
  ctiApi,
  describeChanges,
  refang,
  relativeAge,
  scoreTone,
  type CtiChange,
  type CtiDetail,
  type CtiNote,
  type EnrichmentOption,
  type Opinion,
  type Tlp,
} from './ctiApi';

type Reload = () => Promise<void>;

function useBusy() {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ error: boolean; text: string }>();
  const run = async (work: () => Promise<string | void>) => {
    setBusy(true); setMessage(undefined);
    try { const text = await work(); if (text) setMessage({ error: false, text }); }
    catch (reason) { setMessage({ error: true, text: reason instanceof Error ? reason.message : String(reason) }); }
    finally { setBusy(false); }
  };
  const alert = message && <p role={message.error ? 'alert' : 'status'} className={cn('text-[13px]', message.error ? 'text-destructive' : 'text-muted-foreground')}>{message.text}</p>;
  return { busy, run, alert };
}

const OPINION_LABEL: Record<Opinion, string> = {
  'strongly-disagree': 'Strongly disagree', disagree: 'Disagree', neutral: 'Neutral', agree: 'Agree', 'strongly-agree': 'Strongly agree',
};

/** Analyst notes and STIX opinions on one record. */
export function NotesPanel({ object, reload }: { object: CtiDetail; reload: Reload }) {
  const [kind, setKind] = useState<'note' | 'opinion'>('note');
  const [body, setBody] = useState('');
  const [opinion, setOpinion] = useState<Opinion>('agree');
  const [tlp, setTlp] = useState<Tlp>(object.tlp);
  const [editing, setEditing] = useState<CtiNote>();
  const action = useBusy();
  useEffect(() => { setTlp(object.tlp); }, [object.id, object.tlp]);
  const reset = () => { setBody(''); setEditing(undefined); setKind('note'); };
  return (
    <Panel title={`Notes & opinions (${object.notes.length})`} icon={MessageSquareText} description="Analyst comments and STIX opinions linked to this record. Exported with it when their TLP allows.">
      {object.notes.length > 0 && (
        <ul className="mb-4 space-y-3">
          {object.notes.map(note => (
            <li key={note.id} className="rounded-md border border-border p-3">
              <div className="mb-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                {note.kind === 'opinion' && note.opinion && <Badge variant="secondary">{OPINION_LABEL[note.opinion]}</Badge>}
                <Badge className={cn('font-mono uppercase', TLP_TONE[note.tlp])}>TLP:{note.tlp}</Badge>
                <span>{relativeAge(note.updatedAt)}{note.revision > 0 ? ' · edited' : ''}</span>
                <span className="ml-auto flex gap-1">
                  <Button variant="ghost" size="icon-sm" aria-label="Edit note" onClick={() => { setEditing(note); setKind(note.kind); setBody(note.body); setTlp(note.tlp); if (note.opinion) setOpinion(note.opinion); }}><Pencil /></Button>
                  <Button variant="ghost" size="icon-sm" aria-label="Delete note" onClick={() => { if (window.confirm('Delete this note?')) void action.run(async () => { await ctiApi.deleteNote(note.id); await reload(); }); }}><Trash2 /></Button>
                </span>
              </div>
              {note.body && <p className="whitespace-pre-wrap text-[13px]">{note.body}</p>}
            </li>
          ))}
        </ul>
      )}
      <div className="grid gap-2 sm:grid-cols-3">
        <Choice label="Type" value={kind} onChange={value => setKind(value as 'note' | 'opinion')} disabled={!!editing}
          options={[{ value: 'note', label: 'Note' }, { value: 'opinion', label: 'Opinion' }]} layout="stacked" />
        {kind === 'opinion' && <Choice label="Opinion" value={opinion} onChange={value => setOpinion(value as Opinion)} options={OPINIONS.map(value => ({ value, label: OPINION_LABEL[value] }))} layout="stacked" />}
        <Choice label="TLP" value={tlp} onChange={value => setTlp(value as Tlp)} options={TLP_LEVELS} layout="stacked" />
        <Field label={kind === 'opinion' ? 'Explanation' : 'Note'} layout="stacked" className="sm:col-span-3">
          <Textarea rows={3} value={body} onChange={event => setBody(event.target.value)} />
        </Field>
      </div>
      {action.alert}
      <div className="mt-2 flex gap-2">
        <Button size="sm" disabled={action.busy || (kind === 'note' && !body.trim())} onClick={() => void action.run(async () => {
          if (editing) await ctiApi.updateNote(editing.id, { body, opinion: kind === 'opinion' ? opinion : null, tlp, revision: editing.revision });
          else await ctiApi.addNote(object.id, { kind, body, opinion: kind === 'opinion' ? opinion : null, tlp });
          reset();
          await reload();
        })}>{editing ? 'Save note' : kind === 'opinion' ? 'Add opinion' : 'Add note'}</Button>
        {editing && <Button size="sm" variant="ghost" onClick={reset}>Cancel</Button>}
      </div>
    </Panel>
  );
}

/** Sightings (when and where the record was seen) and, for indicators, the decaying score they drive. */
export function SightingsPanel({ object, reload }: { object: CtiDetail; reload: Reload }) {
  const [where, setWhere] = useState('');
  const [count, setCount] = useState('1');
  const [seenAt, setSeenAt] = useState('');
  const [observed, setObserved] = useState('');
  const action = useBusy();
  if (!SIGHTABLE.includes(object.kind)) return null;
  const isIndicator = object.kind === 'indicator';
  return (
    <Panel title={`Sightings (${object.sightings.length})`} icon={Eye}
      description={isIndicator
        ? `Score ${object.score ?? '–'}/100: confidence plus recent sightings, halved every ${object.halfLifeDays ?? '–'} days without activity. Last activity ${relativeAge(object.lastSighted ?? object.lastSeen ?? object.createdAt)}.`
        : 'When and where this was observed. Each sighting also widens the record’s seen window.'}
      actions={isIndicator ? <Badge className={cn('font-mono', scoreTone(object.score))} title="Indicator score">score {object.score ?? '–'}</Badge> : undefined}>
      {object.sightings.length > 0 && (
        <ul className="mb-4 space-y-1 text-[13px]">
          {object.sightings.map(sighting => (
            <li key={sighting.id} className="flex flex-wrap items-center gap-x-2">
              <span className="font-medium">{sighting.count}×</span>
              <span>{sighting.where || 'unspecified location'}</span>
              <span className="text-muted-foreground">{new Date(sighting.lastSeen).toLocaleString()} · via {sighting.source}</span>
              {sighting.observed.length > 0 && <code className="text-xs text-muted-foreground">{sighting.observed.slice(0, 3).join(', ')}</code>}
              <Button variant="ghost" size="icon-sm" className="ml-auto" aria-label="Delete sighting" onClick={() => void action.run(async () => { await ctiApi.deleteSighting(sighting.id); await reload(); })}><Trash2 /></Button>
            </li>
          ))}
        </ul>
      )}
      <div className="grid gap-2 sm:grid-cols-3">
        <Field label="Where (sensor, org, feed)" layout="stacked"><Input value={where} onChange={event => setWhere(event.target.value)} placeholder="honeypot-eu" /></Field>
        <Field label="Count" layout="stacked"><Input type="number" min={1} value={count} onChange={event => setCount(event.target.value)} /></Field>
        <Field label="Seen at (default now)" layout="stacked"><Input type="datetime-local" value={seenAt} onChange={event => setSeenAt(event.target.value)} /></Field>
        <Field label="Observed values (comma-separated)" layout="stacked" className="sm:col-span-3"><Input value={observed} onChange={event => setObserved(event.target.value)} /></Field>
      </div>
      {action.alert}
      <Button size="sm" className="mt-2" disabled={action.busy} onClick={() => void action.run(async () => {
        const at = seenAt ? new Date(seenAt).toISOString() : new Date().toISOString();
        const result = await ctiApi.addSighting(object.id, { firstSeen: at, lastSeen: at, count: Math.max(1, Number(count) || 1), where,
          observed: observed.split(',').map(value => refang(value)).filter(Boolean) });
        setObserved(''); setSeenAt('');
        await reload();
        return result.recorded ? 'Sighting recorded.' : 'That sighting was already recorded.';
      })}>Record sighting</Button>
    </Panel>
  );
}

const PROVIDER_LABEL: Record<string, string> = {
  'crt.sh': 'crt.sh certificates',
  urlscan: 'urlscan.io',
  'passive-dns': 'Passive DNS',
  'blockchain-explorer': 'Blockchain explorer',
};

/** One-click OSINT lookups that log themselves and ingest what they find. */
export function ConnectorsPanel({ object, reload }: { object: CtiDetail; reload: Reload }) {
  const [options, setOptions] = useState<EnrichmentOption[]>([]);
  const [last, setLast] = useState<{ summary: string; url?: string | null }>();
  const action = useBusy();
  useEffect(() => {
    let live = true;
    void ctiApi.enrichmentOptions(object.id).then(result => { if (live) setOptions(result.providers); }).catch(() => { if (live) setOptions([]); });
    return () => { live = false; };
  }, [object.id, object.revision]);
  if (options.length === 0) return null;
  const run = (provider: string, force: boolean) => action.run(async () => {
    const result = await ctiApi.enrich(object.id, provider, force);
    setLast({ summary: result.summary, url: result.resultUrl });
    await reload();
    setOptions((await ctiApi.enrichmentOptions(object.id)).providers);
    if (result.reused) return `${PROVIDER_LABEL[provider]} already ran in the last 10 minutes; showing that result.`;
    if (result.status === 'failed') return `${PROVIDER_LABEL[provider]} failed; the failure is logged.`;
    return `${PROVIDER_LABEL[provider]}: ${result.findings} findings, ${result.created ?? 0} new records.`;
  });
  return (
    <Panel title="Automatic enrichment" icon={Plug} description={`Runs a lookup for ${options[0].query}, logs it to the enrichment log and links what it finds. Discovered records inherit this record's TLP.`}>
      <ul className="space-y-2">
        {options.map(option => (
          <li key={option.provider} className="flex flex-wrap items-center gap-2 text-[13px]">
            <Button size="sm" variant="outline" disabled={action.busy} onClick={() => void run(option.provider, false)}>Run {PROVIDER_LABEL[option.provider] ?? option.provider}</Button>
            <span className="text-muted-foreground">{option.lastRunAt ? `last run ${relativeAge(option.lastRunAt)}` : 'never run'}</span>
            {option.lastRunAt && <Button size="sm" variant="ghost" disabled={action.busy} onClick={() => void run(option.provider, true)}>Run again</Button>}
          </li>
        ))}
      </ul>
      {action.alert}
      {last && <p className="mt-2 text-[13px]">{last.summary}{last.url && <> · <LinkOut url={last.url} label="open result" /></>}</p>}
      <p className="mt-2 text-xs text-muted-foreground">The server makes these requests. A urlscan.io API key, if you have one, is stored as the <code>urlscanApiKey</code> server credential.</p>
    </Panel>
  );
}

const ACTION_LABEL: Record<string, string> = {
  inferred: 'inferred', retracted: 'inference retracted', sighted: 'sighted', 'note-added': 'note added', 'opinion-added': 'opinion added',
  'note-updated': 'note edited', 'note-deleted': 'note deleted', 'sighting-deleted': 'sighting deleted', 'capsule-built': 'capsule built',
};

/** One journal entry, with field-level old and new values. */
export function ChangeLine({ change }: { change: CtiChange }) {
  const lines = describeChanges(change.detail);
  return (
    <li className="text-[13px]">
      <div className="flex flex-wrap gap-x-2">
        <span className="text-muted-foreground">{new Date(change.at).toLocaleString()}</span>
        <span className="font-medium">{ACTION_LABEL[change.action] ?? change.action}</span>
        {typeof change.detail.type === 'string' && <span className="text-muted-foreground">{change.detail.type} → {String(change.detail.targetName ?? change.detail.targetId)}</span>}
        {typeof change.detail.rule === 'string' && <Badge variant="outline" className="font-mono">{change.detail.rule}</Badge>}
        {change.action === 'sighted' && <span className="text-muted-foreground">{String(change.detail.count)}× {String(change.detail.where || '')}</span>}
        <span className="text-muted-foreground">via {change.source}</span>
      </div>
      {lines.length > 0 && (
        <ul className="ml-4 mt-0.5 list-disc text-xs text-muted-foreground">
          {lines.map(line => <li key={line} className="break-words">{line}</li>)}
        </ul>
      )}
    </li>
  );
}

export function HistoryPanel({ history }: { history: CtiChange[] }) {
  return (
    <Panel title="History" icon={History} description="Append-only change journal for this record, with old and new values.">
      {history.length === 0 ? <p className="text-[13px] text-muted-foreground">No history.</p> : (
        <ol className="space-y-2">{history.map(change => <ChangeLine key={change.seq} change={change} />)}</ol>
      )}
    </Panel>
  );
}
