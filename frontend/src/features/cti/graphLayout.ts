export interface Point { x: number; y: number }

/**
 * Deterministic Fruchterman–Reingold layout. Nodes start on a circle in input
 * order, so the same graph always draws the same way (no random seed), and the
 * focus node, when given, is pinned to the centre.
 */
export function forceLayout(
  ids: string[],
  edges: Array<{ sourceId: string; targetId: string }>,
  width: number,
  height: number,
  options: { iterations?: number; focus?: string } = {},
): Map<string, Point> {
  const iterations = options.iterations ?? 250;
  const n = ids.length;
  const positions = new Map<string, Point>();
  if (n === 0) return positions;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) * 0.4;
  ids.forEach((id, index) => {
    const angle = (2 * Math.PI * index) / n;
    positions.set(id, id === options.focus ? { x: cx, y: cy } : { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
  });
  if (n === 1) { positions.set(ids[0], { x: cx, y: cy }); return positions; }
  const k = Math.sqrt((width * height) / n) * 0.8;
  const valid = edges.filter(edge => positions.has(edge.sourceId) && positions.has(edge.targetId) && edge.sourceId !== edge.targetId);
  let temperature = Math.min(width, height) / 8;
  const cooling = temperature / (iterations + 1);
  for (let step = 0; step < iterations; step++) {
    const shift = new Map<string, Point>(ids.map(id => [id, { x: 0, y: 0 }]));
    for (let i = 0; i < n; i++) {
      const a = positions.get(ids[i])!;
      for (let j = i + 1; j < n; j++) {
        const b = positions.get(ids[j])!;
        let dx = a.x - b.x; let dy = a.y - b.y;
        let distance = Math.hypot(dx, dy);
        if (distance < 0.01) { dx = 0.01 * (i - j); dy = 0.01; distance = Math.hypot(dx, dy); }
        const force = (k * k) / distance;
        const sa = shift.get(ids[i])!; const sb = shift.get(ids[j])!;
        sa.x += (dx / distance) * force; sa.y += (dy / distance) * force;
        sb.x -= (dx / distance) * force; sb.y -= (dy / distance) * force;
      }
    }
    for (const edge of valid) {
      const a = positions.get(edge.sourceId)!; const b = positions.get(edge.targetId)!;
      const dx = a.x - b.x; const dy = a.y - b.y;
      const distance = Math.max(0.01, Math.hypot(dx, dy));
      const force = (distance * distance) / k;
      const sa = shift.get(edge.sourceId)!; const sb = shift.get(edge.targetId)!;
      sa.x -= (dx / distance) * force; sa.y -= (dy / distance) * force;
      sb.x += (dx / distance) * force; sb.y += (dy / distance) * force;
    }
    for (const id of ids) {
      if (id === options.focus) continue;
      const point = positions.get(id)!; const delta = shift.get(id)!;
      const length = Math.max(0.01, Math.hypot(delta.x, delta.y));
      const move = Math.min(length, temperature);
      point.x = Math.min(width - 24, Math.max(24, point.x + (delta.x / length) * move));
      point.y = Math.min(height - 24, Math.max(24, point.y + (delta.y / length) * move));
    }
    temperature = Math.max(0.5, temperature - cooling);
  }
  return positions;
}
