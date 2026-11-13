import { useState } from 'react';
import { FileSpreadsheet } from 'lucide-react';
import { Button, Checkbox, Label } from '@/ui';
import { Choice, Panel } from '../workspace/viewkit';
import { KINDS, TAXONOMY, ctiApi, describeError, type CsvReport, type CtiKind } from './ctiApi';
import { csvTemplate } from './csv';
import { downloadText } from './download';

/** CSV bulk import: validate every row first, then import all valid rows in one transaction. */
export function CtiCsvPanel() {
  const [kind, setKind] = useState<CtiKind>('indicator');
  const [csv, setCsv] = useState<{ name: string; text: string }>();
  const [skipInvalid, setSkipInvalid] = useState(false);
  const [report, setReport] = useState<CsvReport>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  const run = async (dryRun: boolean) => {
    if (!csv) return;
    setBusy(true); setError(undefined);
    try { setReport(await ctiApi.importCsv(kind, csv.text, { dryRun, skipInvalid })); }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };

  return (
    <Panel title="CSV bulk import" icon={FileSpreadsheet}
      description={<>One kind per file. Columns are the core fields and the kind's attributes; list cells use <code>;</code>. A <code>rel:&lt;type&gt;</code> column links each row to <code>&lt;kind&gt;:&lt;dedupe key&gt;</code>, e.g. <code>rel:attributed-to</code> = <code>actor:tronzitveca</code>. Re-importing a file changes nothing.</>}>
      <div className="flex flex-wrap items-end gap-2">
        <Choice label="Kind" value={kind} onChange={value => { setKind(value as CtiKind); setReport(undefined); }} options={KINDS.map(value => ({ value, label: TAXONOMY.kinds[value].title }))} layout="stacked" className="w-56" />
        <Button variant="outline" size="sm" onClick={() => downloadText(`cti-${kind}-template.csv`, csvTemplate(kind))}>Download template</Button>
      </div>
      <Label htmlFor="cti-csv-file" className="mt-3 block text-[13px]">CSV file (UTF-8, up to 5,000 rows)</Label>
      <input id="cti-csv-file" type="file" accept=".csv,text/csv" className="mt-1 block text-[13px]" disabled={busy}
        onChange={event => {
          const file = event.target.files?.[0];
          event.target.value = '';
          setReport(undefined); setError(undefined);
          if (!file) return;
          if (file.size > 5 * 1024 * 1024) { setError('CSV files are limited to 5 MiB.'); return; }
          void file.text().then(text => setCsv({ name: file.name, text }));
        }} />
      {csv && <p className="mt-1 text-xs text-muted-foreground">{csv.name}</p>}
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button size="sm" variant="outline" disabled={!csv || busy} onClick={() => void run(true)}>Validate</Button>
        <Button size="sm" disabled={!csv || busy || (report !== undefined && report.errorCount > 0 && !skipInvalid)} onClick={() => void run(false)}>Import</Button>
        <div className="flex items-center gap-2"><Checkbox id="cti-csv-skip" checked={skipInvalid} onCheckedChange={checked => setSkipInvalid(checked === true)} /><Label htmlFor="cti-csv-skip" className="text-[13px]">Skip invalid rows</Label></div>
      </div>
      {error && <p role="alert" className="mt-2 text-[13px] text-destructive">{error}</p>}
      {report && (
        <div className="mt-3 text-[13px]" role="status">
          <p>{report.rows} rows · {report.valid} valid · {report.errorCount} {report.errorCount === 1 ? 'error' : 'errors'}{report.imported && report.result ? ` · imported: ${report.result.created} created, ${report.result.updated} updated, ${report.result.unchanged} unchanged, ${report.result.relationshipsCreated} links` : report.errorCount ? ' · nothing imported' : ' · ready to import'}</p>
          {report.errors.length > 0 && (
            <table className="mt-2 w-full text-left text-xs">
              <thead><tr><th className="pr-2">Line</th><th className="pr-2">Column</th><th>Problem</th></tr></thead>
              <tbody>{report.errors.map((row, index) => <tr key={`${row.row}-${index}`}><td className="pr-2">{row.row}</td><td className="pr-2">{row.column ?? '–'}</td><td>{describeError(row.code, 400)}</td></tr>)}</tbody>
            </table>
          )}
        </div>
      )}
    </Panel>
  );
}
