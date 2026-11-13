import { describe, expect, it } from 'vitest';
import { KINDS, TAXONOMY, allowedRelationships, cleanAttributes, defang, outgoingTypes, refang, targetKinds } from '../ctiApi';
import { forceLayout } from '../graphLayout';
import { attributeSummary, kindView } from '../kinds';
import { CTI_RUNBOOKS } from '../runbooks';
import { parseSteps } from '../../workspace/workspaceTools/runbooks';

describe('CTI taxonomy helpers', () => {
  it('refangs and defangs shared indicators', () => {
    expect(refang(' hxxps://evil[.]example(.)ink/x ')).toBe('https://evil.example.ink/x');
    expect(refang('apollo[@]mail[dot]com')).toBe('apollo@mail.com');
    expect(defang('https://evil.example.ink')).toBe('hxxps://evil[.]example[.]ink');
    expect(refang(defang('https://evil.example.ink'))).toBe('https://evil.example.ink');
  });

  it('mirrors the server relationship rules', () => {
    expect(allowedRelationships('identity', 'actor')).toEqual(expect.arrayContaining(['attributed-to', 'alias-of', 'related-to']));
    expect(allowedRelationships('infrastructure', 'actor')).not.toContain('uses');
    expect(allowedRelationships('lead', 'malware')).toEqual(['concerns', 'related-to']);
    expect(outgoingTypes('enrichment')).toEqual(['enriches', 'related-to']);
    expect(targetKinds('indicator', 'based-on')).toEqual(['infrastructure', 'malware', 'identity']);
    expect(targetKinds('lead', 'concerns')).toEqual(KINDS);
    expect(targetKinds('victim', 'uses')).toEqual([]);
  });

  it('cleans form drafts into server attributes', () => {
    expect(cleanAttributes('actor', { aliases: 'Tr1030109, 0xapp123,\nTr1030109', ttps: '', motivation: 'personal-gain', attribution: '  handle reuse  ' }))
      .toEqual({ aliases: ['Tr1030109', '0xapp123'], motivation: 'personal-gain', attribution: 'handle reuse' });
    expect(cleanAttributes('infrastructure', { infraKind: 'domain', value: 'evil[.]ink' })).toEqual({ infraKind: 'domain', value: 'evil.ink' });
    expect(cleanAttributes('disclosure', { recipient: 'SEAL', capsuleSha256: 'forged', includeVictims: false })).toEqual({ recipient: 'SEAL', includeVictims: false });
    expect(cleanAttributes('watch', { watchType: 'wallet', target: 'T1', findings: '3' })).toEqual({ watchType: 'wallet', target: 'T1', findings: 3 });
  });

  it('maps every kind to its plugin view and keeps victims privacy-gated', () => {
    expect(KINDS.map(kindView)).toEqual(KINDS.map(kind => TAXONOMY.kinds[kind].plugin));
    expect(TAXONOMY.kinds.victim.private).toBe(true);
    expect(TAXONOMY.kinds.victim.attributes.contactChannel.private).toBe(true);
    expect(attributeSummary('victim', { exposureType: 'wallet-drain' })).toBe('redacted · wallet-drain');
    expect(attributeSummary('identity', { identityType: 'handle', platform: 'GitHub' })).toBe('handle · GitHub');
  });

  it('ships runbooks that Executable Runbooks can parse', () => {
    for (const runbook of CTI_RUNBOOKS) expect(parseSteps(runbook.markdown).length).toBeGreaterThanOrEqual(5);
  });
});

describe('CTI graph layout', () => {
  const ids = ['a', 'b', 'c', 'd', 'e', 'f'];
  const edges = [{ sourceId: 'a', targetId: 'b' }, { sourceId: 'b', targetId: 'c' }, { sourceId: 'd', targetId: 'e' }, { sourceId: 'x', targetId: 'a' }];
  it('is deterministic, in bounds, and pins the focus at the centre', () => {
    const first = forceLayout(ids, edges, 800, 600, { focus: 'a' });
    const second = forceLayout(ids, edges, 800, 600, { focus: 'a' });
    expect([...first.entries()]).toEqual([...second.entries()]);
    expect(first.get('a')).toEqual({ x: 400, y: 300 });
    for (const point of first.values()) {
      expect(point.x).toBeGreaterThanOrEqual(24); expect(point.x).toBeLessThanOrEqual(776);
      expect(point.y).toBeGreaterThanOrEqual(24); expect(point.y).toBeLessThanOrEqual(576);
    }
    const distance = (p: string, q: string) => Math.hypot(first.get(p)!.x - first.get(q)!.x, first.get(p)!.y - first.get(q)!.y);
    expect(distance('d', 'e')).toBeLessThan(distance('d', 'c'));
    expect(forceLayout([], [], 10, 10).size).toBe(0);
  });
});
