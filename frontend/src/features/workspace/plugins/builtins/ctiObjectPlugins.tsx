import { CtiObjectsView } from '../../../cti/CtiObjectsView';
import { TAXONOMY, type CtiKind } from '../../../cti/ctiApi';
import { KIND_ICONS } from '../../../cti/kinds';
import type { PluginModule, WorkspaceViewProps } from '../types';

/** Every CTI view sits in one Work section; these are its subsections, in sidebar order. */
export const CTI_SECTION = 'Threat Intelligence';
export const CTI_SUBSECTIONS = {
  adversaries: 'Adversaries',
  observables: 'Observables',
  investigation: 'Investigation',
  disclosure: 'Victims & disclosure',
  exchange: 'Exchange',
} as const;

const PLACEMENT: Record<CtiKind, { order: number; subsection: string }> = {
  actor: { order: 20, subsection: CTI_SUBSECTIONS.adversaries },
  campaign: { order: 21, subsection: CTI_SUBSECTIONS.adversaries },
  malware: { order: 22, subsection: CTI_SUBSECTIONS.adversaries },
  identity: { order: 30, subsection: CTI_SUBSECTIONS.observables },
  infrastructure: { order: 31, subsection: CTI_SUBSECTIONS.observables },
  indicator: { order: 32, subsection: CTI_SUBSECTIONS.observables },
  lead: { order: 40, subsection: CTI_SUBSECTIONS.investigation },
  watch: { order: 41, subsection: CTI_SUBSECTIONS.investigation },
  enrichment: { order: 42, subsection: CTI_SUBSECTIONS.investigation },
  victim: { order: 50, subsection: CTI_SUBSECTIONS.disclosure },
  disclosure: { order: 51, subsection: CTI_SUBSECTIONS.disclosure },
};

const SHORT: Record<CtiKind, string> = {
  actor: 'Actors', identity: 'Identities', infrastructure: 'Infrastructure', malware: 'Malware', indicator: 'Indicators',
  campaign: 'Campaigns', victim: 'Victims', lead: 'Leads', watch: 'Watches', enrichment: 'Enrichment', disclosure: 'Disclosures',
};

export function ctiObjectPlugin(kind: CtiKind, extra?: Parameters<typeof CtiObjectsView>[0]['extraPanel']): PluginModule {
  const spec = TAXONOMY.kinds[kind];
  const view = (props: WorkspaceViewProps) => <CtiObjectsView {...props} kind={kind} extraPanel={extra} />;
  return { activate(ctx) { ctx.addView({ id: spec.plugin, label: SHORT[kind], icon: KIND_ICONS[kind], order: PLACEMENT[kind].order, section: CTI_SECTION, subsection: PLACEMENT[kind].subsection, mode: 'cti', component: view }); } };
}
