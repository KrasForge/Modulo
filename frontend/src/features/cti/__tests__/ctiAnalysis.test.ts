import { describe, expect, it } from 'vitest';
import { ATTACK, matrix, searchTechniques, techniqueName, techniqueUrl } from '../attack';
import { csvTemplate } from '../csv';
import { describeChanges, scoreTone } from '../ctiApi';

describe('ATT&CK library', () => {
  it('names techniques and sub-techniques from the bundled MITRE data', () => {
    expect(ATTACK.techniques.length).toBeGreaterThan(500);
    expect(techniqueName('t1059.007')).toBe('Command and Scripting Interpreter: JavaScript');
    expect(techniqueName('T9999')).toBeUndefined();
    expect(techniqueUrl('T1059.007')).toBe('https://attack.mitre.org/techniques/T1059/007/');
    expect(searchTechniques('javascript').map(entry => entry.id)).toContain('T1059.007');
    expect(searchTechniques('T1195')[0].id).toBe('T1195');
  });

  it('builds the matrix in tactic order with sub-techniques under their parent', () => {
    const columns = matrix();
    expect(columns.map(column => column.tactic.shortname)).toEqual(ATTACK.tactics.map(tactic => tactic.shortname));
    const execution = columns.find(column => column.tactic.shortname === 'execution')!;
    const interpreter = execution.techniques.find(entry => entry.id === 'T1059')!;
    expect(interpreter.subs.map(sub => sub.id)).toContain('T1059.007');
    expect(columns.flatMap(column => column.techniques).every(entry => !entry.parent)).toBe(true);
  });
});

describe('journal and scoring helpers', () => {
  it('describes field-level changes', () => {
    expect(describeChanges({
      fields: ['status', 'attributes.priority', 'labels'],
      changes: { status: { from: 'open', to: 'closed' }, 'attributes.priority': { from: 'P2', to: null }, labels: { from: [], to: ['npm'] } },
    })).toEqual(['status: open → closed', 'priority: P2 → ∅', 'labels: ∅ → npm']);
    expect(describeChanges({ fields: ['attributes'] })).toEqual([]);
  });

  it('tones scores by detection usefulness', () => {
    expect(scoreTone(80)).toContain('destructive');
    expect(scoreTone(30)).toContain('warning');
    expect(scoreTone(5)).toContain('muted');
    expect(scoreTone(null)).toContain('muted');
  });

  it('matches the server CSV template', () => {
    expect(csvTemplate('indicator')).toBe('name,status,tlp,confidence,labels,firstSeen,lastSeen,description,indicatorType,value,pattern,validFrom,validUntil,source,toIds\n');
    expect(csvTemplate('disclosure')).not.toContain('capsuleSha256');
  });
});
