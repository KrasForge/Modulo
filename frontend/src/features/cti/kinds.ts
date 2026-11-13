import { Bug, Crosshair, Eye, FileWarning, Fingerprint, Flag, Megaphone, Network, Search, ShieldAlert, UserX, type LucideIcon } from 'lucide-react';
import { TAXONOMY, type CtiKind } from './ctiApi';

export const KIND_ICONS: Record<CtiKind, LucideIcon> = {
  actor: Crosshair,
  identity: Fingerprint,
  infrastructure: Network,
  malware: Bug,
  indicator: ShieldAlert,
  campaign: Flag,
  victim: UserX,
  lead: Search,
  watch: Eye,
  enrichment: FileWarning,
  disclosure: Megaphone,
};

/** Graph colours: one hue per kind, all from the theme's chart tokens. */
export const KIND_COLORS: Record<CtiKind, string> = {
  actor: 'hsl(var(--destructive))',
  identity: 'hsl(var(--warning))',
  infrastructure: 'hsl(var(--info))',
  malware: 'hsl(var(--primary))',
  indicator: 'hsl(var(--success))',
  campaign: 'hsl(var(--foreground))',
  victim: 'hsl(var(--muted-foreground))',
  lead: 'hsl(var(--muted-foreground))',
  watch: 'hsl(var(--muted-foreground))',
  enrichment: 'hsl(var(--muted-foreground))',
  disclosure: 'hsl(var(--muted-foreground))',
};

/** Workspace route of the plugin view that owns a kind. */
export const kindView = (kind: CtiKind): string => TAXONOMY.kinds[kind].plugin;

/** One-line summary of the identifying attributes, shown under a record's name. */
export function attributeSummary(kind: CtiKind, attributes: Record<string, unknown>): string {
  const pick = (...keys: string[]) => keys.map(key => attributes[key]).filter(value => value !== undefined && value !== '' && !Array.isArray(value)).map(String);
  switch (kind) {
    case 'actor': return [...(Array.isArray(attributes.aliases) ? [`aka ${(attributes.aliases as string[]).slice(0, 3).join(', ')}`] : []), ...pick('motivation')].join(' · ');
    case 'identity': return pick('identityType', 'platform', 'chain').join(' · ');
    case 'infrastructure': return pick('infraKind', 'hosting', 'asn').join(' · ');
    case 'malware': return pick('role', 'family').join(' · ');
    case 'indicator': return pick('indicatorType', 'source', 'validUntil').join(' · ');
    case 'campaign': return pick('clusterType', 'branch').join(' · ');
    case 'victim': return [attributes.redacted === false ? 'not redacted' : 'redacted', ...pick('exposureType')].join(' · ');
    case 'lead': return pick('number', 'priority', 'nextStep').join(' · ');
    case 'watch': return pick('watchType', 'schedule', 'lastResult').join(' · ');
    case 'enrichment': return pick('provider', 'resultSummary').join(' · ');
    case 'disclosure': return pick('recipient', 'disclosureType', 'reference').join(' · ');
    default: return '';
  }
}
