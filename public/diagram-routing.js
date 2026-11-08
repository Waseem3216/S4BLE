/* Obstacle-aware orthogonal connectors. A missing route is safer than a false line through a resource. */
globalThis.SableRouting = (() => {
  function hits(a, b, r) {
    if (a.x === b.x) return a.x > r.left && a.x < r.right && Math.max(a.y,b.y) > r.top && Math.min(a.y,b.y) < r.bottom;
    if (a.y === b.y) return a.y > r.top && a.y < r.bottom && Math.max(a.x,b.x) > r.left && Math.min(a.x,b.x) < r.right;
    return true;
  }
  function clean(points) {
    const result = [];
    for (const p of points) {
      const last = result.at(-1);
      if (last && last.x === p.x && last.y === p.y) continue;
      while (result.length > 1) {
        const a = result.at(-2), b = result.at(-1);
        // Collapse only straight continuation; never erase a reversal at a port.
        const straightX = a.x === b.x && b.x === p.x && (b.y-a.y)*(p.y-b.y) >= 0;
        const straightY = a.y === b.y && b.y === p.y && (b.x-a.x)*(p.x-b.x) >= 0;
        if (straightX || straightY) result.pop(); else break;
      }
      result.push(p);
    }
    return result;
  }
  function outward(port, point) {
    if (port.side === 'right') return point.x > port.x && point.y === port.y;
    if (port.side === 'left') return point.x < port.x && point.y === port.y;
    if (port.side === 'top') return point.y < port.y && point.x === port.x;
    return point.y > port.y && point.x === port.x;
  }
  function route(from, to, obstacles, width, height, index = 0, occupied = []) {
    const offset = 16 + (index % 4) * 5;
    const escape = p => ({x:p.x + (p.side === 'right' ? offset : p.side === 'left' ? -offset : 0), y:p.y + (p.side === 'bottom' ? offset : p.side === 'top' ? -offset : 0)});
    const s = escape(from), t = escape(to);
    const candidates = [[from,s,{x:t.x,y:s.y},t,to], [from,s,{x:s.x,y:t.y},t,to]];
    const xs = new Set([12,width-12,(s.x+t.x)/2]);
    const ys = new Set([72,height-12,(s.y+t.y)/2]);
    for (const r of obstacles) {
      xs.add(r.left-offset); xs.add(r.right+offset);
      ys.add(r.top-offset); ys.add(r.bottom+offset);
    }
    for (const x of xs) if (x >= 8 && x <= width-8) candidates.push([from,s,{x,y:s.y},{x,y:t.y},t,to]);
    for (const y of ys) if (y >= 8 && y <= height-8) candidates.push([from,s,{x:s.x,y},{x:t.x,y},t,to]);
    let best = null, bestScore = Infinity;
    for (const candidate of candidates) {
      const points = clean(candidate);
      if (points.some(p => p.x < 0 || p.y < 0 || p.x > width || p.y > height)) continue;
      if (!outward(from, points[1]) || !outward(to, points.at(-2))) continue;
      let score = points.length * 18, blocked = false;
      for (let i=1;i<points.length;i++) {
        const a=points[i-1], b=points[i];
        if (obstacles.some(r => hits(a,b,r))) { blocked=true; break; }
        score += Math.abs(a.x-b.x)+Math.abs(a.y-b.y);
        for (const [c,d] of occupied) {
          if (a.x===b.x && c.x===d.x && Math.abs(a.x-c.x)<7) score += Math.max(0,Math.min(Math.max(a.y,b.y),Math.max(c.y,d.y))-Math.max(Math.min(a.y,b.y),Math.min(c.y,d.y)))*3;
          if (a.y===b.y && c.y===d.y && Math.abs(a.y-c.y)<7) score += Math.max(0,Math.min(Math.max(a.x,b.x),Math.max(c.x,d.x))-Math.max(Math.min(a.x,b.x),Math.min(c.x,d.x)))*3;
          const cross = a.x===b.x && c.y===d.y && a.x>Math.min(c.x,d.x) && a.x<Math.max(c.x,d.x) && c.y>Math.min(a.y,b.y) && c.y<Math.max(a.y,b.y);
          const reverseCross = a.y===b.y && c.x===d.x && c.x>Math.min(a.x,b.x) && c.x<Math.max(a.x,b.x) && a.y>Math.min(c.y,d.y) && a.y<Math.max(c.y,d.y);
          if (cross || reverseCross) score += 36;
        }
      }
      if (!blocked && score < bestScore) { best=points; bestScore=score; }
    }
    if (best) for (let i=1;i<best.length;i++) occupied.push([best[i-1],best[i]]);
    return best;
  }
  return {route,hits};
})();
