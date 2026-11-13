import { CtiObjectsView } from '../../../cti/CtiObjectsView';
import { TAXONOMY, type CtiKind } from '../../../cti/ctiApi';
import { KIND_ICONS } from '../../../cti/kinds';
import type { PluginModule, WorkspaceViewProps } from '../types';

/** Sidebar order inside the Threat Intelligence section; the dashboard is 10. */
const ORDER: Record<CtiKind, number> = {
  actor: 20, identity: 21, infrastructure: 22, malware: 23, indicator: 24, campaign: 25, victim: 26,
  lead: 30, watch: 31, enrichment: 32, disclosure: 33,
};

const SHORT: Record<CtiKind, string> = {
  actor: 'Actors', identity: 'Identities', infrastructure: 'Infrastructure', malware: 'Malware', indicator: 'Indicators',
  campaign: 'Campaigns', victim: 'Victims', lead: 'Leads', watch: 'Watches', enrichment: 'Enrichment', disclosure: 'Disclosures',
};

export function ctiObjectPlugin(kind: CtiKind, extra?: Parameters<typeof CtiObjectsView>[0]['extraPanel']): PluginModule {
  const spec = TAXONOMY.kinds[kind];
  const view = (props: WorkspaceViewProps) => <CtiObjectsView {...props} kind={kind} extraPanel={extra} />;
  return { activate(ctx) { ctx.addView({ id: spec.plugin, label: SHORT[kind], icon: KIND_ICONS[kind], order: ORDER[kind], mode: 'cti', component: view }); } };
}
