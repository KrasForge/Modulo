import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { WorkspaceViewProps } from '../../workspace/plugins/types';

const { request } = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock('../../../services/authenticatedRequest', () => ({ authenticatedRequest: request }));

import { CtiObjectsView } from '../CtiObjectsView';

const actor = {
  id: '11111111-1111-1111-1111-111111111111', kind: 'actor', name: 'TronzitVeca', naturalKey: 'tronzitveca', status: 'active', tlp: 'amber',
  confidence: 70, description: '', attributes: { aliases: ['Tr1030109'] }, labels: [], firstSeen: null, lastSeen: null, source: 'manual',
  revision: 3, createdAt: '2026-11-01T00:00:00Z', updatedAt: '2026-11-12T00:00:00Z', degree: 1,
};
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

beforeEach(() => {
  request.mockReset();
  request.mockImplementation(async (path: string, init?: RequestInit) => {
    if (path.startsWith('/api/cti/objects?')) return json({ items: [actor], total: 1, page: 0, limit: 50, hasMore: false });
    if (path === `/api/cti/objects/${actor.id}`) return json({ ...actor, relationships: [{
      id: 'r1', type: 'attributed-to', direction: 'incoming', sourceId: 'i1', targetId: actor.id, confidence: 80, description: '', tlp: 'amber',
      firstSeen: null, lastSeen: null, source: 'watch:x', other: { id: 'i1', kind: 'identity', name: 'apollo1030109', status: 'active', tlp: 'amber' },
    }], history: [{ seq: 1, objectId: actor.id, kind: 'actor', name: 'TronzitVeca', action: 'created', detail: {}, source: 'manual', at: '2026-11-01T00:00:00Z' }] });
    if (path === '/api/cti/objects' && init?.method === 'POST') return json({ ...actor, id: '22222222-2222-2222-2222-222222222222', name: JSON.parse(String(init.body)).name });
    if (path === '/api/cti/objects' ) return json({ code: 'CTI_DUPLICATE_OBJECT' }, 409);
    return json({ code: 'NOT_MOCKED' }, 404);
  });
});

const props = { navigateView: vi.fn() } as unknown as WorkspaceViewProps;

describe('CtiObjectsView', () => {
  it('lists records and opens a detail with relationships and history', async () => {
    render(<MemoryRouter><CtiObjectsView {...props} kind="actor" /></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: 'Open TronzitVeca' }));
    expect(await screen.findByText('apollo1030109')).toBeTruthy();
    expect(screen.getByText('← attributed-to')).toBeTruthy();
    expect(screen.getByText('Tr1030109')).toBeTruthy();
    expect(screen.getAllByText(/created/).length).toBeGreaterThan(0);
  });

  it('creates a record with cleaned attributes and shows classified errors', async () => {
    render(<MemoryRouter><CtiObjectsView {...props} kind="actor" /></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: /New threat actor/ }));
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'PolinRider' } });
    fireEvent.change(screen.getByLabelText('Aliases'), { target: { value: 'PR, PR' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create threat actor' }));
    await waitFor(() => expect(request.mock.calls.some(([path, init]) => path === '/api/cti/objects' && init?.method === 'POST')).toBe(true));
    const [, init] = request.mock.calls.find(([path, options]) => path === '/api/cti/objects' && options?.method === 'POST')!;
    const body = JSON.parse(String(init.body));
    expect(body).toMatchObject({ kind: 'actor', name: 'PolinRider', tlp: 'amber', attributes: { aliases: ['PR'] } });
  });
});
