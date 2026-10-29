/* =============================================================================
   Bug Bounty Hunter — DOM XSS taint engine
   Flow-insensitive dataflow over JavaScript source text: finds values that
   come from a tainted source (location.hash, message data, storage…) and reach
   a dangerous sink (innerHTML, eval, document.write…), following the value
   through variables and one level of function parameters.

   No parser, no dependencies — but also no illusions: this is a heuristic
   analyzer that works on readable code. It reports the chain it followed so a
   human can verify each line, and it ranks by confidence.

   Loaded by the content script, the popup and the Node tests.
   ============================================================================= */

const TaintEngine = (function () {
  'use strict';

  const MAX_CODE = 400000;    // skip giant bundles
  const MAX_LINES = 15000;
  const MAX_FLOWS = 60;
  const MAX_WEAKNESSES = 20;
  const MAX_HOPS = 6;

  // ==========================================================================
  // Sources — where attacker-influenced data enters the page
  // ==========================================================================

  const SOURCES = [
    { re: /\blocation\s*\.\s*(?:search|hash|href)\b/, name: 'location.search/hash/href' },
    { re: /\bwindow\s*\.\s*location\b/, name: 'window.location' },
    { re: /\bdocument\s*\.\s*(?:URL|documentURI|referrer|baseURI)\b/, name: 'document.URL/referrer' },
    { re: /\bdocument\s*\.\s*cookie\b/, name: 'document.cookie' },
    { re: /\b(?:local|session)Storage\b/, name: 'web storage' },
    { re: /\bwindow\s*\.\s*name\b/, name: 'window.name' },
    { re: /\bhistory\s*\.\s*state\b/, name: 'history.state' },
    { re: /\bURLSearchParams\b/, name: 'URLSearchParams' },
    { re: /\b(?:event|e|evt|ev|msg|message)\s*\.\s*data\b/, name: 'message event.data' },
    { re: /\bdataTransfer\b/, name: 'drag-and-drop data' },
    { re: /\$\([^)]*\)\s*\.\s*val\s*\(\s*\)/, name: 'jQuery .val()' },
    { re: /\.\s*value\b/, name: 'form field value' },
    { re: /\bdocument\s*\.\s*(?:getElementById|querySelector|getElementsByClassName|getElementsByName)\s*\([^)]*\)\s*\.\s*(?:value|innerHTML|textContent)\b/, name: 'DOM read' },
    { re: /\bnew\s+URL\s*\(/, name: 'URL object' },
  ];

  const GENERIC_SOURCE_RE = /value|storage|DOM read|message/i;

  // ==========================================================================
  // Sinks — where tainted data becomes executable or markup
  // ==========================================================================

  const SINKS = [
    { re: /\.(?:innerHTML|outerHTML)\s*\+?=/, name: 'innerHTML/outerHTML assignment', severity: 'High' },
    { re: /\.insertAdjacentHTML\s*\(/, name: 'insertAdjacentHTML', severity: 'High' },
    { re: /\bdocument\s*\.\s*write(?:ln)?\s*\(/, name: 'document.write', severity: 'High' },
    { re: /\beval\s*\(/, name: 'eval()', severity: 'High' },
    { re: /\bFunction\s*\(/, name: 'Function constructor', severity: 'High' },
    { re: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/, name: 'setTimeout/setInterval with string', severity: 'High' },
    { re: /\.globalEval\s*\(/, name: 'jQuery globalEval', severity: 'High' },
    { re: /\.(?:html|append|prepend|after|before|replaceWith)\s*\(/, name: 'jQuery HTML injection', severity: 'Medium' },
    { re: /location\s*\.\s*(?:href\s*=|assign\s*\(|replace\s*\()/, name: 'navigation sink', severity: 'Medium' },
    { re: /\bsetAttribute\s*\(\s*["'](?:on\w+|srcdoc|href|src)["']/, name: 'setAttribute sink', severity: 'Medium' },
    { re: /\.srcdoc\s*=/, name: 'srcdoc assignment', severity: 'High' },
    { re: /\.(?:src|href)\s*=(?!=)/, name: 'URL assignment', severity: 'Low' },
    { re: /\bdocument\s*\.\s*domain\s*=/, name: 'document.domain assignment', severity: 'Medium' },
    { re: /\bcreateContextualFragment\s*\(/, name: 'createContextualFragment', severity: 'Medium' },
    { re: /\binsertAdjacentElement\s*\(/, name: 'insertAdjacentElement', severity: 'Medium' },
    { re: /\bpostMessage\s*\(/, name: 'postMessage', severity: 'Low' },
  ];

  const KEYWORDS = new Set([
    'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while',
    'do', 'switch', 'case', 'break', 'continue', 'new', 'delete', 'typeof',
    'instanceof', 'in', 'of', 'this', 'null', 'undefined', 'true', 'false',
    'try', 'catch', 'finally', 'throw', 'async', 'await', 'yield', 'class',
    'extends', 'super', 'import', 'export', 'from', 'default', 'void',
  ]);

  const ASSIGN_RE = /([A-Za-z_$][\w$]*)\s*(\+=|=)(?![=>])/g;
  const TOKEN_RE = /[A-Za-z_$][\w$]*/g;

  // ==========================================================================
  // Text preparation
  // ==========================================================================

  function stripComments(code) {
    return code
      .replace(/\/\*[\s\S]*?\*\//g, match => match.replace(/[^\n]/g, ' '))
      .replace(/(^|[^:\\])\/\/[^\n]*/g, (m, p1) => p1);
  }

  // Replace string/template literal *contents* with spaces (keeps positions).
  function blankStrings(text) {
    let out = '';
    let quote = null;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quote) {
        if (c === '\\') { out += '  '; i++; continue; }
        if (c === quote) { quote = null; out += c; continue; }
        out += ' ';
        continue;
      }
      if (c === '"' || c === "'" || c === '`') { quote = c; out += c; continue; }
      out += c;
    }
    return out;
  }

  function sourcesIn(text) {
    const found = [];
    for (const s of SOURCES) if (s.re.test(text)) found.push(s.name);
    return found;
  }

  function refsIn(text) {
    const blanked = blankStrings(text);
    TOKEN_RE.lastIndex = 0;
    const refs = new Set();
    let m;
    while ((m = TOKEN_RE.exec(blanked)) !== null) {
      const name = m[0];
      if (KEYWORDS.has(name)) continue;
      const before = blanked[m.index - 1];
      if (before === '.' || before === '@') continue;
      // Skip object keys / labels: `{ name: ... }`
      if (blanked[m.index + name.length] === ':') continue;
      refs.add(name);
    }
    return Array.from(refs);
  }

  function parseParams(list) {
    return String(list || '').split(',').map(p => {
      const cleaned = p.trim().replace(/^\.\.\./, '').split('=')[0].trim();
      const m = cleaned.match(/^[A-Za-z_$][\w$]*/);
      return m ? m[0] : null;
    }).filter(Boolean);
  }

  function trimText(text, max) {
    const t = String(text || '').trim().replace(/\s+/g, ' ');
    return t.length > max ? t.slice(0, max) + '…' : t;
  }

  // ==========================================================================
  // Analysis
  // ==========================================================================

  function analyze(rawCode) {
    const result = { flows: [], weaknesses: [], stats: {} };
    if (!rawCode || typeof rawCode !== 'string') return result;

    const code = rawCode.length > MAX_CODE ? rawCode.slice(0, MAX_CODE) : rawCode;
    const stripped = stripComments(code);
    const rawLines = code.split('\n');
    const lines = stripped.split('\n');
    const blankedLines = lines.map(blankStrings);

    const lineCount = Math.min(lines.length, MAX_LINES);

    // ---- functions: name, params, body span -------------------------------
    const functions = [];
    const FN_PATTERNS = [
      { re: /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/, brace: true },
      { re: /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/, brace: false },
      { re: /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>/, brace: false },
      { re: /\b([A-Za-z_$][\w$]*)\s*=\s*function\s*\(([^)]*)\)/, brace: true },
    ];

    for (let i = 0; i < lineCount; i++) {
      for (const pat of FN_PATTERNS) {
        const m = lines[i].match(pat.re);
        if (!m) continue;
        const name = m[1];
        const params = parseParams(m[2]);
        let start = i;
        let end = i;
        // Walk braces from the header line for a body span.
        if (blankedLines[i].includes('{')) {
          let depth = 0;
          let opened = false;
          for (let j = i; j < lineCount; j++) {
            for (const ch of blankedLines[j]) {
              if (ch === '{') { depth++; opened = true; }
              else if (ch === '}') depth--;
            }
            if (opened && depth <= 0) { end = j; break; }
            if (j === lineCount - 1) end = j;
          }
        }
        functions.push({ name, params, start, end, id: functions.length });
        break;
      }
    }

    function enclosingFunction(lineNo) {
      let best = null;
      for (const fn of functions) {
        if (lineNo >= fn.start && lineNo <= fn.end) {
          if (!best || fn.start >= best.start) best = fn;
        }
      }
      return best;
    }

    // ---- assignments, calls ------------------------------------------------
    const assignments = [];
    const calls = [];
    const CALL_RE = /\b([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/g;

    for (let i = 0; i < lineCount; i++) {
      const line = lines[i];
      if (!line || line.length > 4000) continue;

      ASSIGN_RE.lastIndex = 0;
      let a;
      while ((a = ASSIGN_RE.exec(line)) !== null) {
        const name = a[1];
        const idx = a.index + a[0].indexOf(name);
        if (idx > 0 && line[idx - 1] === '.') continue;
        if (KEYWORDS.has(name)) continue;
        let rhs = line.slice(ASSIGN_RE.lastIndex);
        const semi = rhs.indexOf(';');
        if (semi >= 0) rhs = rhs.slice(0, semi);
        if (!rhs.trim()) continue;
        assignments.push({ name, rhs, line: i, text: rawLines[i] });
      }

      CALL_RE.lastIndex = 0;
      let c;
      while ((c = CALL_RE.exec(line)) !== null) {
        const before = line.slice(Math.max(0, c.index - 12), c.index);
        if (/\bfunction\s+$/.test(before)) continue; // definition, not a call
        if (KEYWORDS.has(c[1])) continue;
        calls.push({ name: c[1], args: c[2], line: i, index: c.index });
      }
    }

    // ---- build the taint graph --------------------------------------------
    // Nodes: "v:<var>" and "p:<fnId>:<paramIndex>"
    const best = new Map();   // node -> chain (array of steps)
    const edges = [];         // { from, to, steps: [step] }

    const step = (line, kind, text, extra) => Object.assign({ line, kind, text: trimText(rawLines[line], 150) }, extra || {});

    function nodeFor(name, lineNo) {
      const fn = enclosingFunction(lineNo);
      if (fn) {
        const pi = fn.params.indexOf(name);
        if (pi >= 0) return 'p:' + fn.id + ':' + pi;
      }
      return 'v:' + name;
    }

    function seedDirect(node, sourceName, lineNo) {
      const chain = [step(lineNo, 'source', rawLines[lineNo], { source: sourceName })];
      const cur = best.get(node);
      if (!cur || chain.length < cur.length) best.set(node, chain);
    }

    for (const asg of assignments) {
      const srcs = sourcesIn(blankStrings(asg.rhs));
      const target = nodeFor(asg.name, asg.line);
      if (srcs.length) seedDirect(target, srcs[0], asg.line);
      for (const ref of refsIn(asg.rhs)) {
        const from = nodeFor(ref, asg.line);
        if (from === target) continue;
        edges.push({ from, to: target, steps: [step(asg.line, 'assign', rawLines[asg.line])] });
      }
    }

    const byName = new Map();
    for (const fn of functions) {
      if (!byName.has(fn.name)) byName.set(fn.name, []);
      byName.get(fn.name).push(fn);
    }

    for (const call of calls) {
      const targets = byName.get(call.name);
      if (!targets) continue;
      const args = call.args.split(',');
      for (const fn of targets) {
        fn.params.forEach((param, pi) => {
          const argText = args[pi];
          if (!argText || !argText.trim()) return;
          const to = 'p:' + fn.id + ':' + pi;
          const srcs = sourcesIn(blankStrings(argText));
          if (srcs.length) {
            // Keep the call and the parameter in the chain — that is the part
            // a human needs to see: data enters here, arrives there.
            const chain = [
              step(call.line, 'source', rawLines[call.line], { source: srcs[0] }),
              step(call.line, 'call', rawLines[call.line], { into: call.name + '()' }),
              step(fn.start, 'param', rawLines[fn.start], { param: fn.params[pi] }),
            ];
            const cur = best.get(to);
            if (!cur || chain.length < cur.length) best.set(to, chain);
            return;
          }
          for (const ref of refsIn(argText)) {
            const from = nodeFor(ref, call.line);
            edges.push({
              from, to,
              steps: [
                step(call.line, 'call', rawLines[call.line], { into: call.name + '(' + (fn.params[pi] || '') + ')' }),
                step(fn.start, 'param', rawLines[fn.start], { param: fn.params[pi] }),
              ],
            });
          }
        });
      }
    }

    // Relax over the edges (bounded, so cycles cannot loop forever).
    for (let pass = 0; pass < MAX_HOPS + 2; pass++) {
      let changed = false;
      for (const e of edges) {
        const from = best.get(e.from);
        if (!from) continue;
        if (from.length > MAX_HOPS) continue;
        const cand = from.concat(e.steps);
        const cur = best.get(e.to);
        if (!cur || cand.length < cur.length) {
          best.set(e.to, cand);
          changed = true;
        }
      }
      if (!changed) break;
    }

    // ---- sinks -------------------------------------------------------------
    const flows = [];
    const seen = new Set();

    const emit = (sinkName, severity, lineNo, context, chain, sourceName) => {
      const key = sinkName + '@' + lineNo + '#' + sourceName;
      if (seen.has(key)) return;
      seen.add(key);

      // hops counts value movements: one step per variable/parameter the
      // value crosses before reaching the sink.
      const hops = Math.max(1, chain.length);
      let score = 0.95 - 0.07 * Math.max(0, hops - 1);
      if (GENERIC_SOURCE_RE.test(sourceName)) score -= 0.08;
      if (chain[0] && chain[0].originChecked) score -= 0.15;
      score = Math.max(0.35, Math.min(0.98, score));

      flows.push({
        id: key,
        sink: {
          name: sinkName,
          severity,
          line: lineNo + 1,
          snippet: trimText(rawLines[lineNo], 220),
        },
        source: { name: sourceName, line: chain[0].line + 1 },
        steps: chain.concat([step(lineNo, 'sink', rawLines[lineNo], { sink: sinkName })]),
        hops,
        score: Math.round(score * 100) / 100,
        confidence: score >= 0.8 ? 'high' : score >= 0.55 ? 'medium' : 'low',
      });
    };

    for (let i = 0; i < lineCount; i++) {
      const line = lines[i];
      if (!line || line.length > 6000) continue;

      for (const sink of SINKS) {
        const m = line.match(sink.re);
        if (!m || m.index === undefined) continue;

        let context = line.slice(m.index);
        const semi = context.indexOf(';');
        if (semi >= 0) context = context.slice(0, semi);

        const directSources = sourcesIn(blankStrings(context));
        if (directSources.length && chainIsMeaningful(context)) {
          const chain = [step(i, 'source', rawLines[i], { source: directSources[0] })];
          emit(sink.name, sink.severity, i, context, chain, directSources[0]);
          continue;
        }

        const refs = refsIn(context);
        let bestFlow = null;
        for (const ref of refs) {
          const node = nodeFor(ref, i);
          const chain = best.get(node);
          if (!chain) continue;
          if (!bestFlow || chain.length < bestFlow.chain.length) {
            bestFlow = { chain, source: chain[0].source || 'tainted value' };
          }
        }
        if (bestFlow) {
          // A validated postMessage handler (origin checked above the sink in
          // the same function) is still reported, but ranked lower.
          const fn = enclosingFunction(i);
          const scope = fn ? lines.slice(fn.start, i + 1).join('\n') : '';
          if (/\.origin\b/.test(scope) && /message|event\.data|\.data\b/i.test(bestFlow.source)) {
            bestFlow.chain[0].originChecked = true;
          }
          emit(sink.name, sink.severity, i, context, bestFlow.chain, bestFlow.source);
        }
      }
    }

    // A sink match like `.src =` inside its own source expression is not a
    // flow unless the right-hand side really carries data.
    function chainIsMeaningful(context) {
      return /[=\s(]/.test(context) && context.length > 3;
    }

    flows.sort((a, b) => b.score - a.score || a.sink.line - b.sink.line);
    result.flows = flows.slice(0, MAX_FLOWS);

    // ---- weaknesses: message listeners without origin validation ----------
    const WEAK_LINES = [
      /addEventListener\s*\(\s*["']message["']/,
      /\bonmessage\s*=/,
      /\.onmessage\s*=/,
    ];
    for (let i = 0; i < lineCount && result.weaknesses.length < MAX_WEAKNESSES; i++) {
      if (!WEAK_LINES.some(re => re.test(lines[i]))) continue;
      const windowText = lines.slice(i, Math.min(lineCount, i + 14)).join('\n');
      if (/\.origin\b/.test(windowText)) continue;
      const already = result.weaknesses.some(w => Math.abs(w.line - (i + 1)) <= 2);
      if (already) continue;
      result.weaknesses.push({
        type: 'Message listener without origin check',
        severity: 'medium',
        line: i + 1,
        snippet: trimText(rawLines[i], 220),
        note: 'postMessage handlers should compare event.origin against an allow-list before using event.data.',
      });
    }

    result.stats = {
      lines: lineCount,
      truncated: code.length < rawCode.length,
      assignments: assignments.length,
      calls: calls.length,
      functions: functions.length,
      sinks: flows.length,
    };
    return result;
  }

  return { analyze, SOURCES, SINKS };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = TaintEngine;
}
