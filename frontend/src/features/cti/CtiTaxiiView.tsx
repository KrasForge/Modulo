import { useCallback, useEffect, useState } from 'react';
import { CloudDownload, KeyRound, Rss, Share2, Trash2 } from 'lucide-react';
import { Badge, Button, Checkbox, Input, Label, cn } from '@/ui';
import { Choice, EmptyPanel, Field, FieldGroup, ListRow, ListRows, Panel, ViewShell } from '../workspace/viewkit';
import { TLP_LEVELS, TLP_TONE, ctiApi, relativeAge, type IssuedToken, type TaxiiCollection, type TaxiiFeed, type Tlp } from './ctiApi';

/** TAXII 2.1: publish TLP-capped collections to partners, and subscribe to partner feeds. */
export function CtiTaxiiView() {
  const [collections, setCollections] = useState<TaxiiCollection[]>([]);
  const [feeds, setFeeds] = useState<TaxiiFeed[]>([]);
  const [issued, setIssued] = useState<IssuedToken & { collection: string }>();
  const [message, setMessage] = useState<{ error: boolean; text: string }>();
  const [busy, setBusy] = useState(false);

  const run = useCallback(async (work: () => Promise<string | void>) => {
    setBusy(true); setMessage(undefined);
    try { const text = await work(); if (text) setMessage({ error: false, text }); }
    catch (reason) { setMessage({ error: true, text: reason instanceof Error ? reason.message : String(reason) }); }
    finally { setBusy(false); }
  }, []);
  const load = useCallback(() => run(async () => {
    const [nextCollections, nextFeeds] = await Promise.all([ctiApi.taxiiCollections(), ctiApi.taxiiFeeds()]);
    setCollections(nextCollections); setFeeds(nextFeeds);
  }), [run]);
  useEffect(() => { void load(); }, [load]);

  const apiRoot = `${window.location.origin}/api/taxii2/root/`;

  return (
    <ViewShell title="TAXII" icon={Share2} subtitle="Publish collections to partners over TAXII 2.1 and pull partner collections on a schedule.">
      {message && <p role={message.error ? 'alert' : 'status'} className={cn('mb-4 rounded-md border px-3 py-2 text-[13px]', message.error ? 'border-destructive/40 text-destructive' : 'border-border text-muted-foreground')}>{message.text}</p>}
      {issued && (
        <Panel title="Token issued — copy it now" icon={KeyRound} className="mb-4"
          description="The secret is shown once. Give the partner the API root, the collection ID and either the Basic credentials or the bearer token."
          actions={<Button size="sm" variant="ghost" onClick={() => setIssued(undefined)}>Done</Button>}>
          <dl className="grid gap-x-4 gap-y-1 text-[13px] sm:grid-cols-[10rem_1fr]">
            <dt className="text-muted-foreground">API root</dt><dd><code className="break-all">{apiRoot}</code></dd>
            <dt className="text-muted-foreground">Collection ID</dt><dd><code className="break-all">{issued.collection}</code></dd>
            <dt className="text-muted-foreground">Basic username</dt><dd><code className="break-all">{issued.username}</code></dd>
            <dt className="text-muted-foreground">Basic password</dt><dd><code className="break-all">{issued.password}</code></dd>
            <dt className="text-muted-foreground">Bearer token</dt><dd><code className="break-all">{issued.bearer}</code></dd>
          </dl>
        </Panel>
      )}
      <div className="grid gap-4 xl:grid-cols-2">
        <div className="space-y-4">
          <Panel title="Published collections" icon={Share2} description={<>Discovery: <code className="break-all">{window.location.origin}/api/taxii2/</code>. Each collection serves your STIX export at or below its TLP ceiling; leads, watches and enrichment are never served.</>}>
            {collections.length === 0 ? <p className="text-[13px] text-muted-foreground">No collections yet.</p> : (
              <ul className="space-y-4">
                {collections.map(collection => (
                  <li key={collection.id} className="rounded-md border border-border p-3">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-medium">{collection.title}</span>
                      <Badge className={cn('font-mono uppercase', TLP_TONE[collection.tlpCeiling])}>≤ TLP:{collection.tlpCeiling}</Badge>
                      {collection.canRead && <Badge variant="outline">read</Badge>}
                      {collection.canWrite && <Badge variant="warning">write</Badge>}
                      {collection.includeVictims && <Badge variant="outline">redacted victims</Badge>}
                      <Button variant="ghost" size="icon-sm" className="ml-auto" aria-label={`Delete collection ${collection.title}`}
                        onClick={() => { if (window.confirm(`Delete “${collection.title}”? Its tokens stop working immediately.`)) void run(async () => { await ctiApi.deleteTaxiiCollection(collection.id); await load(); }); }}><Trash2 /></Button>
                    </div>
                    <p className="mt-1 break-all text-xs text-muted-foreground">ID {collection.id}</p>
                    <ListRows className="mt-2">
                      {collection.tokens.map(token => (
                        <ListRow key={token.id} title={token.label} muted={!!token.revokedAt}
                          detail={token.revokedAt ? `revoked ${relativeAge(token.revokedAt)}` : token.lastUsedAt ? `last used ${relativeAge(token.lastUsedAt)}` : 'never used'}
                          actions={token.revokedAt ? undefined : <Button size="sm" variant="ghost" onClick={() => void run(async () => { await ctiApi.revokeTaxiiToken(token.id); await load(); return `Revoked ${token.label}.`; })}>Revoke</Button>} />
                      ))}
                    </ListRows>
                    <IssueToken disabled={busy} onIssue={label => run(async () => {
                      const token = await ctiApi.createTaxiiToken(collection.id, label);
                      setIssued({ ...token, collection: collection.id });
                      await load();
                    })} />
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <NewCollection disabled={busy} onCreate={input => run(async () => { await ctiApi.createTaxiiCollection(input); await load(); return `Created ${input.title}.`; })} />
        </div>
        <div className="space-y-4">
          <Panel title="Subscribed feeds" icon={Rss} description="Pulls page through objects added since the last pull and import idempotently. Objects without a TLP marking take the feed's default TLP.">
            {feeds.length === 0 ? <EmptyPanel icon={Rss} title="No feeds" description="Add a partner's TAXII 2.1 API root and collection below." /> : (
              <ListRows>
                {feeds.map(feed => (
                  <ListRow key={feed.id} title={feed.title} muted={!feed.enabled}
                    detail={`${feed.apiRoot} · ${feed.collectionId} · ${feed.pollMinutes ? `every ${feed.pollMinutes} min` : 'manual'} · ${feed.lastPolledAt ? `${relativeAge(feed.lastPolledAt)}: ${feed.lastResult}` : 'never pulled'}`}
                    meta={<Badge className={cn('font-mono uppercase', TLP_TONE[feed.defaultTlp])}>TLP:{feed.defaultTlp}</Badge>}
                    actions={<>
                      <Button size="sm" variant="outline" disabled={busy} onClick={() => void run(async () => { const result = await ctiApi.pullTaxiiFeed(feed.id); await load(); return result.result; })}><CloudDownload /> Pull</Button>
                      <Button variant="ghost" size="icon-sm" aria-label={`Delete feed ${feed.title}`} onClick={() => { if (window.confirm(`Delete feed “${feed.title}”? Imported records stay.`)) void run(async () => { await ctiApi.deleteTaxiiFeed(feed.id); await load(); }); }}><Trash2 /></Button>
                    </>} />
                ))}
              </ListRows>
            )}
          </Panel>
          <NewFeed disabled={busy} onCreate={input => run(async () => { await ctiApi.createTaxiiFeed(input); await load(); return `Added ${input.title}.`; })} />
        </div>
      </div>
    </ViewShell>
  );
}

function IssueToken({ disabled, onIssue }: { disabled: boolean; onIssue: (label: string) => Promise<void> }) {
  const [label, setLabel] = useState('');
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      <Input className="min-w-0 flex-1" value={label} onChange={event => setLabel(event.target.value)} placeholder="Partner name" aria-label="Partner name for a new token" />
      <Button size="sm" disabled={disabled} onClick={() => void onIssue(label.trim() || 'Partner').then(() => setLabel(''))}><KeyRound /> Issue token</Button>
    </div>
  );
}

function NewCollection({ disabled, onCreate }: { disabled: boolean; onCreate: (input: { title: string; tlpCeiling: Tlp; includeVictims: boolean; canRead: boolean; canWrite: boolean }) => Promise<void> }) {
  const [title, setTitle] = useState('');
  const [tlp, setTlp] = useState<Tlp>('green');
  const [canWrite, setCanWrite] = useState(false);
  const [canRead, setCanRead] = useState(true);
  const [victims, setVictims] = useState(false);
  return (
    <Panel title="New collection">
      <FieldGroup legend="Collection" columns={2}>
        <Field label="Title"><Input value={title} onChange={event => setTitle(event.target.value)} placeholder="SEAL partners" /></Field>
        <Choice label="TLP ceiling" value={tlp} onChange={value => setTlp(value as Tlp)} options={TLP_LEVELS} />
        <div className="flex items-center gap-2"><Checkbox id="taxii-read" checked={canRead} onCheckedChange={checked => setCanRead(checked === true)} /><Label htmlFor="taxii-read" className="text-[13px]">Partners can read</Label></div>
        <div className="flex items-center gap-2"><Checkbox id="taxii-write" checked={canWrite} onCheckedChange={checked => setCanWrite(checked === true)} /><Label htmlFor="taxii-write" className="text-[13px]">Partners can add objects</Label></div>
        <div className="flex items-center gap-2 sm:col-span-2"><Checkbox id="taxii-victims" checked={victims} onCheckedChange={checked => setVictims(checked === true)} /><Label htmlFor="taxii-victims" className="text-[13px]">Include victims (always pseudonymized when redacted)</Label></div>
      </FieldGroup>
      <Button className="mt-3" size="sm" disabled={disabled || !title.trim()} onClick={() => void onCreate({ title: title.trim(), tlpCeiling: tlp, includeVictims: victims, canRead, canWrite }).then(() => setTitle(''))}>Create collection</Button>
    </Panel>
  );
}

function NewFeed({ disabled, onCreate }: { disabled: boolean; onCreate: (input: { title: string; apiRoot: string; collectionId: string; username?: string; password?: string; defaultTlp: Tlp; pollMinutes?: number | null; enabled: boolean }) => Promise<void> }) {
  const [title, setTitle] = useState('');
  const [apiRoot, setApiRoot] = useState('');
  const [collection, setCollection] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [tlp, setTlp] = useState<Tlp>('amber');
  const [poll, setPoll] = useState('');
  return (
    <Panel title="Subscribe to a feed" description="The password is encrypted on the server and never shown again.">
      <FieldGroup legend="Feed" columns={2}>
        <Field label="Title"><Input value={title} onChange={event => setTitle(event.target.value)} /></Field>
        <Choice label="Default TLP" value={tlp} onChange={value => setTlp(value as Tlp)} options={TLP_LEVELS} />
        <Field label="API root URL" className="sm:col-span-2"><Input type="url" value={apiRoot} onChange={event => setApiRoot(event.target.value)} placeholder="https://partner.example/taxii2/root/" /></Field>
        <Field label="Collection ID" className="sm:col-span-2"><Input value={collection} onChange={event => setCollection(event.target.value)} /></Field>
        <Field label="Username"><Input value={username} onChange={event => setUsername(event.target.value)} autoComplete="off" /></Field>
        <Field label="Password"><Input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="new-password" /></Field>
        <Field label="Poll every (minutes, ≥ 15; empty = manual)"><Input type="number" min={15} value={poll} onChange={event => setPoll(event.target.value)} /></Field>
      </FieldGroup>
      <Button className="mt-3" size="sm" disabled={disabled || !title.trim() || !apiRoot.trim() || !collection.trim()}
        onClick={() => void onCreate({ title: title.trim(), apiRoot: apiRoot.trim(), collectionId: collection.trim(), username: username.trim() || undefined,
          password: password || undefined, defaultTlp: tlp, pollMinutes: poll ? Number(poll) : null, enabled: true }).then(() => { setTitle(''); setApiRoot(''); setCollection(''); setUsername(''); setPassword(''); setPoll(''); })}>Add feed</Button>
    </Panel>
  );
}
