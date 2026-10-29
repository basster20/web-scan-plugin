/* Node unit tests for taint-engine.js (DOM XSS dataflow).
   Run:  node tests/taint.test.js                     */

'use strict';

const path = require('path');
const Taint = require(path.join(__dirname, '..', 'taint-engine.js'));
const Engine = require(path.join(__dirname, '..', 'scan-engine.js'));

let passed = 0;
let failed = 0;

function check(name, cond, detail) {
  if (cond) { passed++; console.log('  ok   ' + name); }
  else { failed++; console.log('  FAIL ' + name + (detail !== undefined ? '  → ' + JSON.stringify(detail) : '')); }
}

const flowsOf = code => Taint.analyze(code).flows;

// ---------------------------------------------------------------------------
console.log('\n[1] direct source → sink');
{
  const f = flowsOf("document.getElementById('out').innerHTML = location.hash;");
  check('one flow found', f.length === 1, f);
  check('sink is innerHTML', f[0] && /innerHTML/.test(f[0].sink.name), f[0] && f[0].sink);
  check('source is location.*', f[0] && /location/.test(f[0].source.name), f[0] && f[0].source);
  check('sink line is 1', f[0] && f[0].sink.line === 1, f[0] && f[0].sink.line);
  check('direct flow scores highest', f[0] && f[0].score >= 0.9, f[0] && f[0].score);
  check('confidence high', f[0] && f[0].confidence === 'high', f[0] && f[0].confidence);
}

// ---------------------------------------------------------------------------
console.log('\n[2] through a local variable');
{
  const f = flowsOf("const h = location.hash.slice(1);\nel.innerHTML = h;");
  check('flow via variable', f.length >= 1, f);
  check('chain has source + sink steps',
    f[0] && f[0].steps[0].kind === 'source' && f[0].steps[f[0].steps.length - 1].kind === 'sink',
    f[0] && f[0].steps.map(s => s.kind));
  check('sink on line 2', f[0] && f[0].sink.line === 2, f[0] && f[0].sink.line);
  check('hops recorded', f[0] && f[0].hops >= 1, f[0] && f[0].hops);
}

// ---------------------------------------------------------------------------
console.log('\n[3] two hops + URLSearchParams');
{
  const code = [
    "let params = new URLSearchParams(location.search);",
    "let q = params.get('q');",
    "out.innerHTML = q;",
  ].join('\n');
  const f = flowsOf(code);
  check('two-hop flow found', f.length >= 1, f);
  check('chain length ≥ 3', f[0] && f[0].steps.length >= 3, f[0] && f[0].steps.length);
  check('score below direct', f[0] && f[0].score < 0.95, f[0] && f[0].score);
}

// ---------------------------------------------------------------------------
console.log('\n[4] function parameters');
{
  const code = [
    'function render(v) {',
    '  document.body.innerHTML = v;',
    '}',
    'render(location.hash);',
  ].join('\n');
  const f = flowsOf(code);
  check('param flow found', f.length >= 1, f);
  check('chain shows call and param',
    f[0] && f[0].steps.some(s => s.kind === 'call') && f[0].steps.some(s => s.kind === 'param'),
    f[0] && f[0].steps.map(s => s.kind));
}

// ---------------------------------------------------------------------------
console.log('\n[5] no false positives');
{
  check('static string is clean', flowsOf("out.innerHTML = 'static markup';").length === 0);
  check('unrelated variable is clean', flowsOf("const x = location.hash;\nobj.innerHTML = safeValue;").length === 0);
  check('string literal containing location.hash is clean',
    flowsOf('const s = "location.hash";\nel.innerHTML = s;').length === 0);
  check('comment is ignored', flowsOf("// el.innerHTML = location.hash;\nconst ok = 1;").length === 0);
}

// ---------------------------------------------------------------------------
console.log('\n[6] sinks beyond innerHTML');
{
  check('document.write', flowsOf('document.write(location.search);').length >= 1);
  check('eval', flowsOf('eval(location.hash);').length >= 1);
  check('jQuery .html()', flowsOf("$('#a').html(location.hash);").length >= 1);
  check('setAttribute on-event', flowsOf("el.setAttribute('onclick', location.hash);").length >= 1);
  check('srcdoc', flowsOf('frame.srcdoc = location.hash;').length >= 1);
  check('insertAdjacentHTML', flowsOf("el.insertAdjacentHTML('beforeend', location.hash);").length >= 1);
}

// ---------------------------------------------------------------------------
console.log('\n[7] message handlers');
{
  const vulnerable = Taint.analyze([
    "window.addEventListener('message', function (e) {",
    '  document.body.innerHTML = e.data;',
    '});',
  ].join('\n'));
  check('missing origin check flagged', vulnerable.weaknesses.length === 1, vulnerable.weaknesses);
  check('weakness line is 1', vulnerable.weaknesses[0] && vulnerable.weaknesses[0].line === 1, vulnerable.weaknesses[0]);
  check('event.data reaches innerHTML', vulnerable.flows.length >= 1, vulnerable.flows);

  const safe = Taint.analyze([
    "window.addEventListener('message', function (e) {",
    "  if (e.origin !== 'https://trusted.example') return;",
    '  document.body.innerHTML = e.data;',
    '});',
  ].join('\n'));
  check('validated handler is not flagged', safe.weaknesses.length === 0, safe.weaknesses);
}

// ---------------------------------------------------------------------------
console.log('\n[8] scan-engine sink coverage added for DOM XSS');
{
  const sinks = Engine.scanSinks("parent.postMessage(data, '*');", 't');
  check('postMessage wildcard origin', sinks.some(s => s.name === 'postMessage wildcard origin'), sinks.map(s => s.name));

  const sinks2 = Engine.scanSinks("el.setAttribute('onclick', 'x()');", 't');
  check('setAttribute event sink', sinks2.some(s => s.name.includes('setAttribute')), sinks2.map(s => s.name));

  const sinks3 = Engine.scanSinks('document.domain = "evil.example";', 't');
  check('document.domain assignment', sinks3.some(s => s.name === 'document.domain assignment'), sinks3.map(s => s.name));
}

// ---------------------------------------------------------------------------
console.log('\n[9] stats and bounds');
{
  const big = Array.from({ length: 400 }, (_, i) => `const v${i} = location.hash;\nel${i}.innerHTML = v${i};`).join('\n');
  const r = Taint.analyze(big);
  check('flows capped at 60', r.flows.length <= 60, r.flows.length);
  check('stats report lines', r.stats.lines === 800, r.stats.lines);
  check('empty input is safe', Taint.analyze('').flows.length === 0);
  check('null input is safe', Taint.analyze(null).flows.length === 0);
}

// ---------------------------------------------------------------------------
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
