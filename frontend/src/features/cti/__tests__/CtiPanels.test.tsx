import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { WorkspaceViewProps } from '../../workspace/plugins/types';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('../../../services/authenticatedRequest', () => ({ authenticatedRequest: request }));

import { CtiObjectsView } from '../CtiObjectsView';
import { CtiAttackView } from '../CtiAttackView';
import { CtiTaxiiView } from '../CtiTaxiiView';

const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });
const T = '2026-11-12T00:00:00Z';
const indicator = {
  id: '11111111-1111-1111-1111-111111111111', kind: 'indicator', name: 'evil.example.ink', naturalKey: 'domain:evil.example.ink', status: 'active',
  tlp: 'amber', confidence: 70, description: '', attributes: { indicatorType: 'domain', value: 'evil.example.ink' }, labels: [], firstSeen: null,
  lastSeen: null, source: 'manual', revision: 1, createdAt: T, updatedAt: T, score: 42, halfLifeDays: 90, lastSighted: T, sightingCount: 1,
};
const actorHead = { id: '22222222-2222-2222-2222-222222222222', kind: 'actor', name: 'TronzitVeca', status: 'active', tlp: 'amber' };
const props = { navigateView: vi.fn() } as unknown as WorkspaceViewProps;

beforeEach(() => {
  request.mockReset();
  request.mockImplementation(async (path: string, init?: RequestInit) => {
    if (path.startsWith('/api/cti/objects?')) return json({ items: [indicator], total: 1, page: 0, limit: 50, hasMore: false });
    if (path === `/api/cti/objects/${indicator.id}`) return json({ ...indicator,
      relationships: [{ id: 'r1', type: 'indicates', direction: 'outgoing', sourceId: indicator.id, targetId: actorHead.id, confidence: 60, description: '',
        tlp: 'amber', firstSeen: null, lastSeen: null, source: 'inference', inferredBy: 'indicator-propagation', other: actorHead }],
      notes: [{ id: 'n1', objectId: indicator.id, kind: 'opinion', opinion: 'agree', body: 'Shared hosting', tlp: 'green', revision: 0, createdAt: T, updatedAt: T }],
      sightings: [{ id: 's1', objectId: indicator.id, firstSeen: T, lastSeen: T, count: 3, where: 'honeypot-eu', source: 'cron:ids', confidence: null, description: '', observed: ['evil.example.ink'], createdAt: T }],
      history: [{ seq: 2, objectId: indicator.id, kind: 'indicator', name: indicator.name, action: 'updated', source: 'manual', at: T,
        detail: { fields: ['status'], changes: { status: { from: 'revoked', to: 'active' } } } }] });
    if (path === `/api/cti/objects/${indicator.id}/enrichment`) return json({ observable: { type: 'domain', value: 'evil.example.ink' },
      providers: [{ provider: 'crt.sh', query: 'evil.example.ink', lastRunAt: null }, { provider: 'passive-dns', query: 'evil.example.ink', lastRunAt: T }] });
    if (path === `/api/cti/objects/${indicator.id}/enrich`) return json({ reused: false, status: 'done', enrichmentId: 'e1', summary: '3 certificates, 2 other hostnames', resultUrl: 'https://crt.sh/?q=%25.evil.example.ink', findings: 2, created: 2 });
    if (path === `/api/cti/objects/${indicator.id}/notes`) return json({ id: 'n2', body: JSON.parse(String(init?.body)).body });
    if (path === `/api/cti/objects/${indicator.id}/sightings`) return json({ id: 's2', recorded: true });
    if (path === '/api/cti/attack') return json({ usage: { 'T1059.007': [actorHead], T9999: [actorHead] } });
    if (path === '/api/cti/taxii/collections' && init?.method === 'POST') return json({ id: 'c1' });
    if (path === '/api/cti/taxii/collections') return json([{ id: 'c1', title: 'SEAL partners', description: '', tlpCeiling: 'green', includeVictims: false,
      canRead: true, canWrite: false, createdAt: T, tokens: [{ id: 't1', label: 'SEAL', createdAt: T, lastUsedAt: null, revokedAt: null }] }]);
    if (path === '/api/cti/taxii/collections/c1/tokens') return json({ id: 't2', label: 'Vendor', username: 't2', password: 'one-time-secret', bearer: 't2.one-time-secret' });
    if (path === '/api/cti/taxii/feeds') return json([{ id: 'f1', title: 'Partner feed', apiRoot: 'https://partner.example/taxii2/root/', collectionId: 'abc',
      username: 'modulo', hasPassword: true, defaultTlp: 'amber', pollMinutes: 60, enabled: true, addedAfter: null, lastPolledAt: T, lastResult: 'Pulled 4 objects' }]);
    if (path === '/api/cti/taxii/feeds/f1/pull') return json({ objects: 4, pages: 1, result: 'Pulled 4 objects in 1 page: 1 created, 0 updated, 3 unchanged' });
    return json({ code: 'NOT_MOCKED' }, 404);
  });
});

const calls = (suffix: string) => request.mock.calls.filter(([path]) => String(path).endsWith(suffix));

describe('record detail panels', () => {
  it('shows score, inferred edges without removal, opinions, sightings and field diffs; runs connectors', async () => {
    render(<MemoryRouter><CtiObjectsView {...props} kind="indicator" /></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: 'Open evil.example.ink' }));
    expect(await screen.findByText('TronzitVeca')).toBeTruthy();
    expect(screen.getAllByText('score 42').length).toBeGreaterThan(0);
    expect(screen.getByText('inferred')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Remove indicates TronzitVeca' })).toBeNull();
    expect(screen.getByText('Agree')).toBeTruthy();
    expect(screen.getByText('honeypot-eu')).toBeTruthy();
    expect(screen.getByText('status: revoked → active')).toBeTruthy();

    fireEvent.click(await screen.findByRole('button', { name: 'Run crt.sh certificates' }));
    expect(await screen.findByText('crt.sh certificates: 2 findings, 2 new records.')).toBeTruthy();
    expect(JSON.parse(String(calls('/enrich')[0][1].body))).toEqual({ provider: 'crt.sh', force: false });

    fireEvent.change(screen.getByLabelText('Where (sensor, org, feed)'), { target: { value: 'ids-1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record sighting' }));
    await waitFor(() => expect(calls('/sightings')).toHaveLength(1));
    expect(JSON.parse(String(calls('/sightings')[0][1].body))).toMatchObject({ where: 'ids-1', count: 1 });

    fireEvent.change(screen.getByLabelText('Note'), { target: { value: 'Rotates weekly' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add note' }));
    await waitFor(() => expect(calls('/notes')).toHaveLength(1));
    expect(JSON.parse(String(calls('/notes')[0][1].body))).toMatchObject({ kind: 'note', body: 'Rotates weekly', tlp: 'amber' });
  });
});

describe('ATT&CK matrix', () => {
  it('colours used techniques and flags unknown IDs', async () => {
    render(<MemoryRouter><CtiAttackView {...props} /></MemoryRouter>);
    expect(await screen.findByText(/Not in the bundled ATT&CK library.*T9999/)).toBeTruthy();
    fireEvent.click(await screen.findByTitle('T1059 Command and Scripting Interpreter'));
    expect(await screen.findByText('TronzitVeca')).toBeTruthy();
  });
});

describe('TAXII view', () => {
  it('issues a token once and pulls a feed', async () => {
    render(<MemoryRouter><CtiTaxiiView /></MemoryRouter>);
    expect(await screen.findByText('SEAL partners')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Partner name for a new token'), { target: { value: 'Vendor' } });
    fireEvent.click(screen.getByRole('button', { name: /Issue token/ }));
    expect(await screen.findByText('one-time-secret')).toBeTruthy();
    expect(screen.getByText('t2.one-time-secret')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /Pull/ }));
    expect(await screen.findByText(/Pulled 4 objects in 1 page/)).toBeTruthy();
  });
});
