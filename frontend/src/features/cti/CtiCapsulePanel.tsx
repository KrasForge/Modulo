import { useState } from 'react';
import { Package } from 'lucide-react';
import { Button } from '@/ui';
import { Panel } from '../workspace/viewkit';
import { ctiApi } from './ctiApi';
import type { CtiDetailExtraProps } from './CtiObjectsView';
import { downloadJson } from './download';

/** Builds and downloads the shareable STIX capsule for one disclosure. */
export function CtiCapsulePanel({ object, reload }: CtiDetailExtraProps) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const concerns = object.relationships.filter(rel => rel.type === 'concerns' && rel.direction === 'outgoing').length;
  const ceiling = typeof object.attributes.tlpCeiling === 'string' ? object.attributes.tlpCeiling : 'green';
  const sha = typeof object.attributes.capsuleSha256 === 'string' ? object.attributes.capsuleSha256 : undefined;
  return (
    <Panel title="Disclosure capsule" icon={Package}
      description={`STIX 2.1 report of the ${concerns} records this disclosure concerns and their one-hop neighbourhood, capped at TLP:${ceiling.toUpperCase()}. Victims ${object.attributes.includeVictims === true ? 'are included only as redacted records' : 'are excluded'}; workflow records are never included.`}>
      {sha && <p className="mb-2 break-all text-[13px]">Last capsule SHA-256: <code>{sha}</code>{typeof object.attributes.capsuleAt === 'string' && ` (${new Date(object.attributes.capsuleAt).toLocaleString()})`}</p>}
      {message && <p role="status" className="mb-2 text-[13px] text-muted-foreground">{message}</p>}
      <Button size="sm" disabled={busy || concerns === 0} onClick={() => void (async () => {
        setBusy(true); setMessage(undefined);
        try {
          const capsule = await ctiApi.capsule(object.id);
          downloadJson(`capsule-${object.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-${capsule.sha256.slice(0, 12)}.json`, capsule.bundle);
          setMessage(`Built ${capsule.objects} STIX objects. SHA-256 ${capsule.sha256}.`);
          await reload();
        } catch (reason) { setMessage(reason instanceof Error ? reason.message : String(reason)); }
        finally { setBusy(false); }
      })()}>{concerns === 0 ? 'Link records with “concerns” first' : 'Build and download capsule'}</Button>
    </Panel>
  );
}
