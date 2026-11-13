// MITRE ATT&CK Enterprise technique library, generated from MITRE's STIX data by
// scripts/generate-attack-library.py and mirrored from shared/cti.
import library from './attack-enterprise.v1.json';

export interface AttackTactic { id: string; shortname: string; name: string }
export interface AttackTechnique { id: string; name: string; tactics: string[]; parent?: string }

export const ATTACK = library as unknown as { attackVersion: string; tactics: AttackTactic[]; techniques: AttackTechnique[] };
const BY_ID = new Map(ATTACK.techniques.map(technique => [technique.id, technique]));

export const technique = (id: string): AttackTechnique | undefined => BY_ID.get(id.toUpperCase());

/** "Parent: Sub-technique" for sub-techniques; the plain name otherwise; undefined when unknown. */
export function techniqueName(id: string): string | undefined {
  const found = technique(id);
  if (!found) return undefined;
  const parent = found.parent ? BY_ID.get(found.parent) : undefined;
  return parent ? `${parent.name}: ${found.name}` : found.name;
}

export const techniqueUrl = (id: string) => `https://attack.mitre.org/techniques/${id.toUpperCase().replace('.', '/')}/`;

/** Top-level techniques per tactic, in matrix order, each with its sub-techniques. */
export function matrix(): Array<{ tactic: AttackTactic; techniques: Array<AttackTechnique & { subs: AttackTechnique[] }> }> {
  const subs = new Map<string, AttackTechnique[]>();
  for (const entry of ATTACK.techniques) if (entry.parent) subs.set(entry.parent, [...(subs.get(entry.parent) ?? []), entry]);
  return ATTACK.tactics.map(tactic => ({
    tactic,
    techniques: ATTACK.techniques
      .filter(entry => !entry.parent && entry.tactics.includes(tactic.shortname))
      .sort((a, b) => a.name.localeCompare(b.name))
      .map(entry => ({ ...entry, subs: subs.get(entry.id) ?? [] })),
  }));
}

/** Techniques whose id or name contains the query, best matches first. */
export function searchTechniques(query: string, limit = 12): AttackTechnique[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return ATTACK.techniques
    .map(entry => ({ entry, label: `${entry.id} ${techniqueName(entry.id)}`.toLowerCase() }))
    .filter(({ label }) => label.includes(q))
    .sort((a, b) => Number(!a.label.startsWith(q)) - Number(!b.label.startsWith(q)) || a.entry.id.localeCompare(b.entry.id))
    .slice(0, limit)
    .map(({ entry }) => entry);
}
