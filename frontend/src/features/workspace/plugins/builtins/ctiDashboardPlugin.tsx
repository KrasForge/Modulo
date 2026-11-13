import { ArrowLeftRight, Grid3x3, LayoutDashboard, Network, Share2 } from 'lucide-react';
import { CtiAttackView } from '../../../cti/CtiAttackView';
import { CtiTaxiiView } from '../../../cti/CtiTaxiiView';
import { CtiDashboardView } from '../../../cti/CtiDashboardView';
import { CtiExchangeView } from '../../../cti/CtiExchangeView';
import { CtiGraphView } from '../../../cti/CtiGraphView';
import type { PluginModule } from '../types';
import { CTI_GROUPS } from './ctiObjectPlugins';

const plugin: PluginModule = {
  activate(ctx) {
    ctx.addView({ id: 'cti-dashboard', label: 'Dashboard', icon: LayoutDashboard, order: 10, section: CTI_GROUPS.overview, mode: 'cti', component: CtiDashboardView });
    ctx.addView({ id: 'cti-graph', label: 'Graph', icon: Network, order: 11, section: CTI_GROUPS.overview, mode: 'cti', component: CtiGraphView });
    ctx.addView({ id: 'cti-attack', label: 'ATT&CK', icon: Grid3x3, order: 12, section: CTI_GROUPS.overview, mode: 'cti', component: CtiAttackView });
    ctx.addView({ id: 'cti-exchange', label: 'STIX / MISP / CSV', icon: ArrowLeftRight, order: 60, section: CTI_GROUPS.exchange, mode: 'cti', component: CtiExchangeView });
    ctx.addView({ id: 'cti-taxii', label: 'TAXII', icon: Share2, order: 61, section: CTI_GROUPS.exchange, mode: 'cti', component: CtiTaxiiView });
  },
};
export default plugin;
