import { TAXONOMY, type CtiKind } from './ctiApi';

/** Header row for a kind, mirroring the server's template. */
export function csvTemplate(kind: CtiKind): string {
  const columns = ['name', 'status', 'tlp', 'confidence', 'labels', 'firstSeen', 'lastSeen', 'description',
    ...Object.entries(TAXONOMY.kinds[kind].attributes).filter(([, spec]) => !spec.readOnly).map(([key]) => key)];
  return `${columns.join(',')}\n`;
}
