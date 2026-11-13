import { CtiObjectsView } from '../../../cti/CtiObjectsView';
import { TAXONOMY, type CtiKind } from '../../../cti/ctiApi';
import { KIND_ICONS } from '../../../cti/kinds';
import type { PluginModule, WorkspaceViewProps } from '../types';

/**
 * Sidebar placement inside Work: the CTI views are grouped from overview to sharing
 * (the dashboard plugin owns the overview and exchange groups).
 */
export const CTI_GROUPS = {
  overview: 'Threat Intelligence',
  adversaries: 'CTI · Adversaries',
  observables: 'CTI · Observables',
  investigation: 'CTI · Investigation',
  disclosure: 'CTI · Victims & disclosure',
  exchange: 'CTI · Exchange',
} as const;

const PLACEMENT: Record<CtiKind, { order: number; section: string }> = {
  actor: { order: 20, section: CTI_GROUPS.adversaries },
  campaign: { order: 21, section: CTI_GROUPS.adversaries },
  malware: { order: 22, section: CTI_GROUPS.adversaries },
  identity: { order: 30, section: CTI_GROUPS.observables },
  infrastructure: { order: 31, section: CTI_GROUPS.observables },
  indicator: { order: 32, section: CTI_GROUPS.observables },
  lead: { order: 40, section: CTI_GROUPS.investigation },
  watch: { order: 41, section: CTI_GROUPS.investigation },
  enrichment: { order: 42, section: CTI_GROUPS.investigation },
  victim: { order: 50, section: CTI_GROUPS.disclosure },
  disclosure: { order: 51, section: CTI_GROUPS.disclosure },
};

const SHORT: Record<CtiKind, string> = {
  actor: 'Actors', identity: 'Identities', infrastructure: 'Infrastructure', malware: 'Malware', indicator: 'Indicators',
  campaign: 'Campaigns', victim: 'Victims', lead: 'Leads', watch: 'Watches', enrichment: 'Enrichment', disclosure: 'Disclosures',
};

export function ctiObjectPlugin(kind: CtiKind, extra?: Parameters<typeof CtiObjectsView>[0]['extraPanel']): PluginModule {
  const spec = TAXONOMY.kinds[kind];
  const view = (props: WorkspaceViewProps) => <CtiObjectsView {...props} kind={kind} extraPanel={extra} />;
  return { activate(ctx) { ctx.addView({ id: spec.plugin, label: SHORT[kind], icon: KIND_ICONS[kind], order: PLACEMENT[kind].order, section: PLACEMENT[kind].section, mode: 'cti', component: view }); } };
}
