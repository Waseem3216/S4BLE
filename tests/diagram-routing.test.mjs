import test from 'node:test';
import assert from 'node:assert/strict';
import '../public/diagram-routing.js';
const {route,hits} = globalThis.SableRouting;
const rect = (x,y,w=238,h=108) => ({left:x,right:x+w,top:y,bottom:y+h});
const port = (r,side) => ({x:side==='right'?r.right+2:r.left-2,y:(r.top+r.bottom)/2,side});
test('dense multi-column diagram routes forward, reverse and vertical dependencies outside every card', () => {
  const boxes = Array.from({length:30},(_,i)=>rect(64+Math.floor(i/6)*338,96+(i%6)*194));
  const occupied=[];
  for (const [a,b] of [[0,24],[24,0],[0,5],[5,0],[2,20],[12,28],[26,7]]) {
    const from=boxes[a],to=boxes[b];
    const forward=to.left>=from.left;
    const same=to.left===from.left;
    const points=route(port(from,forward?'right':'left'),port(to,same||!forward?'right':'left'),boxes,1800,1320,a,occupied);
    assert.ok(points,`${a} to ${b}`);
    for(let i=1;i<points.length;i++) {
      assert.ok(points[i].x===points[i-1].x || points[i].y===points[i-1].y);
      for(const box of boxes) assert.equal(hits(points[i-1],points[i],box),false);
    }
  }
});
test('overview routes across occupied intermediate category cards', () => {
  const boxes=Array.from({length:7},(_,i)=>rect(50+(i%3)*460,80+Math.floor(i/3)*260,350,160));
  for(let a=0;a<7;a++) for(let b=a+1;b<7;b++) {
    const points=route(port(boxes[a],'right'),port(boxes[b],boxes[a].left===boxes[b].left?'right':'left'),boxes,1440,900,a+b);
    assert.ok(points,`${a} to ${b}`);
    for(let i=1;i<points.length;i++) for(const box of boxes) assert.equal(hits(points[i-1],points[i],box),false);
  }
});
test('blocked routes are not misrepresented by lines through cards',()=> {
  assert.equal(route({x:10,y:10,side:'right'},{x:90,y:90,side:'left'},[rect(0,0,100,100)],100,100),null);
});

test('ports retain outward directions, including connections that run backwards', () => {
  const boxes = [rect(60,80), rect(440,80), rect(820,80)];
  for (const [a,b] of [[0,2],[2,0]]) {
    const source = port(boxes[a],a < b ? 'right' : 'left');
    const target = port(boxes[b],a < b ? 'left' : 'right');
    const points = route(source,target,boxes,1180,400);
    assert.ok(points);
    const start = points[1], end = points.at(-2);
    assert.equal(Math.sign(start.x-source.x), source.side === 'right' ? 1 : -1);
    assert.equal(Math.sign(end.x-target.x), target.side === 'right' ? 1 : -1);
    for (const p of points) assert.ok(p.x >= 0 && p.x <= 1180 && p.y >= 0 && p.y <= 400);
  }
});

test('routing works at minimum and maximum zoom without drawing across cards', () => {
  for (const zoom of [.35, 2.2]) {
    const boxes = Array.from({length:6}, (_, i) => rect(64*zoom,64+30*zoom+i*196*zoom,252*zoom,116*zoom));
    const points = route(port(boxes[0],'right'),port(boxes[5],'right'),boxes,380*zoom,64+30*zoom+6*196*zoom);
    assert.ok(points, `zoom ${zoom}`);
    for(let i=1;i<points.length;i++) for(const box of boxes) assert.equal(hits(points[i-1],points[i],box),false);
  }
});

test('a candidate that escapes the drawing surface is omitted', () => {
  const boxes=[rect(0,0,30,30),rect(60,0,30,30)];
  assert.equal(route(port(boxes[0],'left'),port(boxes[1],'right'),boxes,90,30),null);
});

test('category aggregation preserves both direction and evidence confidence', async () => {
  const { readFile } = await import('node:fs/promises');
  const { runInNewContext } = await import('node:vm');
  const source = await readFile(new URL('../public/app.js', import.meta.url),'utf8');
  const snippet = source.slice(source.indexOf('function getCategoryRelationshipPairs('), source.indexOf('function resourceKey('));
  const resourceMap = new Map([['a',{category:'compute'}],['b',{category:'data'}]]);
  const context = { buildArchitectureGraph: () => ({resourceMap,links:[
    {source:'a',target:'b',confidence:'confirmed'},
    {source:'a',target:'b',confidence:'inferred'},
    {source:'b',target:'a',confidence:'confirmed'}
  ]}) };
  runInNewContext(snippet,context);
  const pairs = context.getCategoryRelationshipPairs([]);
  assert.equal(pairs.length,3);
  assert.equal(pairs.filter(pair=>pair.inferred).length,1);
  assert.equal(pairs.filter(pair=>pair.source==='compute').length,2);
  assert.equal(pairs.filter(pair=>pair.source==='data').length,1);
});
