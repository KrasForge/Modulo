import { ArrowLeftRight, LayoutDashboard, Network } from 'lucide-react';
import { CtiDashboardView } from '../../../cti/CtiDashboardView';
import { CtiExchangeView } from '../../../cti/CtiExchangeView';
import { CtiGraphView } from '../../../cti/CtiGraphView';
import type { PluginModule } from '../types';

const plugin: PluginModule = {
  activate(ctx) {
    ctx.addView({ id: 'cti-dashboard', label: 'Dashboard', icon: LayoutDashboard, order: 10, mode: 'cti', component: CtiDashboardView });
    ctx.addView({ id: 'cti-graph', label: 'Graph', icon: Network, order: 11, mode: 'cti', component: CtiGraphView });
    ctx.addView({ id: 'cti-exchange', label: 'STIX / MISP', icon: ArrowLeftRight, order: 40, mode: 'cti', component: CtiExchangeView });
  },
};
export default plugin;
