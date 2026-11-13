import { describe, expect, it } from 'vitest';
import { CATALOG } from '../../workspace/plugins/catalog';
import { hubTabs, viewSectionLabel } from '../../workspace/plugins/modes';
import { PACKS } from '../../workspace/plugins/packs';
import { PluginRuntime } from '../../workspace/plugins/runtime';
import { CTI_PLUGIN_IDS } from '../../workspace/plugins';
import { TAXONOMY } from '../ctiApi';

describe('CTI pack plugins', () => {
  it('installs the whole workbench from the dashboard and groups it under Work → Threat Intelligence', async () => {
    const runtime = new PluginRuntime(CATALOG);
    await runtime.init();
    await runtime.install('cti-dashboard');
    for (const id of CTI_PLUGIN_IDS) expect(runtime.isActive(id), id).toBe(true);
    expect(runtime.isActive('evidence-library')).toBe(true);
    const tabs = hubTabs(runtime.contributions().views, 'work').filter(view => view.mode === 'cti');
    // One Work section; the groups are subsections of it, overview views first.
    expect(new Set(tabs.map(viewSectionLabel))).toEqual(new Set(['Threat Intelligence']));
    expect(tabs.map(view => [view.subsection ?? '', view.id])).toEqual([
      ['', 'cti-dashboard'], ['', 'cti-graph'], ['', 'cti-attack'],
      ['Adversaries', 'cti-actors'], ['Adversaries', 'cti-campaigns'], ['Adversaries', 'cti-malware'],
      ['Observables', 'cti-identities'], ['Observables', 'cti-infrastructure'], ['Observables', 'cti-indicators'],
      ['Investigation', 'cti-leads'], ['Investigation', 'cti-watches'], ['Investigation', 'cti-enrichment'],
      ['Victims & disclosure', 'cti-victims'], ['Victims & disclosure', 'cti-disclosures'],
      ['Exchange', 'cti-exchange'], ['Exchange', 'cti-taxii'],
    ]);
    const work = hubTabs(runtime.contributions().views, 'work').map(viewSectionLabel);
    const first = work.indexOf('Threat Intelligence');
    expect(work.slice(first, first + tabs.length).every(section => section === 'Threat Intelligence')).toBe(true);
    await runtime.dispose();
  });

  it('keeps plugin ids, taxonomy and the catalog pack aligned', () => {
    const kindPlugins = Object.values(TAXONOMY.kinds).map(kind => kind.plugin);
    expect([...kindPlugins, 'cti-dashboard'].sort()).toEqual([...CTI_PLUGIN_IDS].sort());
    const pack = PACKS.find(candidate => candidate.id === 'pack-threat-intelligence')!;
    expect(pack.pluginIds).toEqual(expect.arrayContaining([...CTI_PLUGIN_IDS, 'graph-view', 'executable-runbooks', 'workspace-briefings']));
    for (const id of pack.pluginIds) expect(CATALOG.find(plugin => plugin.id === id)?.load, id).toBeTypeOf('function');
  });
});
