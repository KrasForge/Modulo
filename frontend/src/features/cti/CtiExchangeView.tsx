import { useState } from 'react';
import { ArrowLeftRight, Download, Upload } from 'lucide-react';
import { Button, Checkbox, Input, Label, cn } from '@/ui';
import { Choice, Field, Panel, ViewShell } from '../workspace/viewkit';
import { TLP_LEVELS, ctiApi, type Tlp } from './ctiApi';
import { downloadJson, stamp } from './download';

const INGEST_EXAMPLE = `POST /api/cti/ingest
Authorization: Bearer <access token>

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
}`;

/** STIX 2.1 / MISP export and STIX import, plus the ingest contract for watches. */
export function CtiExchangeView() {
  const [tlp, setTlp] = useState<Tlp>('green');
  const [victims, setVictims] = useState(false);
  const [info, setInfo] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ error: boolean; text: string }>();

  const run = async (work: () => Promise<string>) => {
    setBusy(true); setMessage(undefined);
    try { setMessage({ error: false, text: await work() }); }
    catch (reason) { setMessage({ error: true, text: reason instanceof Error ? reason.message : String(reason) }); }
    finally { setBusy(false); }
  };

  const importFile = (file: File | undefined) => file && void run(async () => {
    if (file.size > 16 * 1024 * 1024) throw new Error('STIX bundles are limited to 16 MiB.');
    let bundle: unknown;
    try { bundle = JSON.parse(await file.text()); } catch { throw new Error('The file is not valid JSON.'); }
    const result = await ctiApi.importStix(bundle);
    const skipped = Object.entries(result.skipped).map(([type, count]) => `${count} ${type}`).join(', ');
    return `Imported: ${result.created} created, ${result.updated} updated, ${result.unchanged} unchanged, ${result.relationshipsCreated} relationships.${skipped ? ` Skipped: ${skipped}.` : ''}`;
  });

  return (
    <ViewShell title="CTI Exchange" icon={ArrowLeftRight} subtitle="STIX 2.1 and MISP interoperability. Exports apply a TLP ceiling and never include leads, watches or enrichment.">
      {message && <p role={message.error ? 'alert' : 'status'} className={cn('mb-4 rounded-md border px-3 py-2 text-[13px]', message.error ? 'border-destructive/40 text-destructive' : 'border-border text-muted-foreground')}>{message.text}</p>}
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Export" icon={Download} description="Only records whose TLP is at or below the ceiling are included; a relationship is included only when both ends are.">
          <div className="space-y-3">
            <Choice label="TLP ceiling" value={tlp} onChange={value => setTlp(value as Tlp)} options={TLP_LEVELS} />
            <div className="flex items-center gap-2"><Checkbox id="cti-export-victims" checked={victims} onCheckedChange={checked => setVictims(checked === true)} /><Label htmlFor="cti-export-victims" className="text-[13px]">Include victims in STIX (redacted victims stay pseudonymous; contact channels are never exported)</Label></div>
            <Field label="MISP event title"><Input value={info} onChange={event => setInfo(event.target.value)} placeholder="Modulo CTI export" /></Field>
            <div className="flex flex-wrap gap-2">
              <Button disabled={busy} onClick={() => void run(async () => {
                const bundle = await ctiApi.exportStix(tlp, victims);
                downloadJson(`modulo-cti-stix-${tlp}-${stamp()}.json`, bundle);
                return `Exported ${(bundle.objects as unknown[]).length} STIX objects.`;
              })}><Download /> STIX 2.1 bundle</Button>
              <Button variant="outline" disabled={busy} onClick={() => void run(async () => {
                const event = await ctiApi.exportMisp(tlp, info || undefined);
                downloadJson(`modulo-cti-misp-${tlp}-${stamp()}.json`, event);
                return `Exported ${((event.Event as { Attribute: unknown[] }).Attribute).length} MISP attributes. Victims are never part of a MISP export.`;
              })}><Download /> MISP event</Button>
            </div>
          </div>
        </Panel>
        <Panel title="Import STIX 2.1" icon={Upload} description="Maps threat actors, intrusion sets, campaigns, malware, indicators, infrastructure and observables onto records. Re-importing the same bundle changes nothing; TLP is never lowered.">
          <Label htmlFor="cti-stix-file" className="text-[13px]">STIX bundle (.json)</Label>
          <input id="cti-stix-file" type="file" accept="application/json,.json" className="mt-2 block text-[13px]" disabled={busy}
            onChange={event => { importFile(event.target.files?.[0]); event.target.value = ''; }} />
        </Panel>
        <Panel title="Feeding the graph from watches" description="Cron watches and agents post findings to the ingest API. Objects are upserted by their dedupe key, lists are unioned, the seen window only widens, and the watch's run is recorded and linked to what it found." className="xl:col-span-2">
          <pre className="overflow-x-auto rounded-md bg-surface-2 p-3 text-xs">{INGEST_EXAMPLE}</pre>
          <p className="mt-2 text-[13px] text-muted-foreground">From a shell, <code>tools/modulo_mcp/cti_ingest.py findings.json</code> posts a batch with the same token the Modulo MCP server uses.</p>
        </Panel>
      </div>
    </ViewShell>
  );
}
