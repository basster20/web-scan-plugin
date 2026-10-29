/* Node unit tests for scan-engine.js — no browser needed.
   Run:  node tests/engine.test.js                                  */

'use strict';

const path = require('path');
const Engine = require(path.join(__dirname, '..', 'scan-engine.js'));

let passed = 0;
let failed = 0;

function check(name, cond, detail) {
  if (cond) {
    passed++;
    console.log('  ok   ' + name);
  } else {
    failed++;
    console.log('  FAIL ' + name + (detail !== undefined ? '  → ' + JSON.stringify(detail) : ''));
  }
}

function types(findings) {
  return findings.map(f => f.type);
}

function has(findings, type) {
  return findings.some(f => f.type === type);
}

// ---------------------------------------------------------------------------
console.log('\n[1] real secrets are found');
{
  const fixture = [
    'AKIAIOSFODNN7EXAMPLE2',                       // 20 chars after AKIA? no — real form below
    'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    'const tok = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";',
    'sk-proj-Abc123def456Ghi789jkl012mno345pqr678stu901',
    'sk_live_51H8xY2LkjhGFDSAqwerZXcvBNM9876543210',
    'SG.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'hf_abcdefghijklmnopqrstuvwxyz123456',
    'private_token = "glpat-XXXXXXXXXXXXXXXXXXXX"',
    'webhook: https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx',
    'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    'mysql://admin:S3cretP@ss@db.example.com:3306/prod',
    'const password = "hunter2secret";',
    'AKIA' + 'IOSFODNN7EXAMPLE'.slice(0, 16),
  ];
  // AWS key (valid form)
  const aws = Engine.scanCredentials('const key = "AKIA" + "ABCDEFGH12345678"; // AKIAIOSFODNN7EXAMPL' + 'E', 't');
  check('AWS Access Key ID', has(aws, 'AWS Access Key ID'), types(aws));

  const priv = Engine.scanCredentials(
    '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PBF1pF+x7UdMORX7St\n-----END RSA PRIVATE KEY-----', 't');
  check('private key block', has(priv, 'Private Key'), types(priv));

  const all = Engine.scanCredentials(fixture.join('\n'), 'fixture');
  const wanted = ['AWS Secret Access Key', 'GitHub Token', 'OpenAI API Key', 'Stripe Live Key',
    'SendGrid API Key', 'Hugging Face Token', 'GitLab Token', 'Slack Webhook', 'JWT', 'MySQL/Connection'];
  check('AWS Secret Access Key', has(all, 'AWS Secret Access Key'), types(all));
  check('GitHub Token', has(all, 'GitHub Token'), types(all));
  check('OpenAI key', has(all, 'OpenAI API Key'), types(all));
  check('Stripe live key', has(all, 'Stripe Live Key'), types(all));
  check('SendGrid key', has(all, 'SendGrid API Key'), types(all));
  check('Hugging Face token', has(all, 'Hugging Face Token'), types(all));
  check('GitLab token', has(all, 'GitLab Token'), types(all));
  check('Slack webhook', has(all, 'Slack Webhook'), types(all));
  check('JWT', has(all, 'JWT'), types(all));
  check('connection string creds', has(all, 'Connection String'), types(all));
  check('plaintext password', has(all, 'Plaintext Password'), types(all));
}

// ---------------------------------------------------------------------------
console.log('\n[2] noise is rejected');
{
  check('Luhn rejects fake card', Engine.luhn('4111111111111111') === false || Engine.luhn('4111111111111112') === false);
  check('Luhn accepts real test card', Engine.luhn('4242424242424242') === true);

  const noise = Engine.scanCredentials(
    'apiKey = "YOUR_API_KEY_HERE";\npassword = "password";\nkey: "${PROCESS_SECRET}"\nhash = "a3f5c8d9e1b2a4f6c8d0e2b4a6f8c0d2e4b6a8f0c2d4e6a8b0c2d4e6f8a0b2c4"', 'noise');
  check('placeholder apiKey rejected', !has(noise, 'API Key (labelled)'), types(noise));
  check('template var rejected', noise.filter(f => f.value.includes('${')).length === 0);
  check('bare hash not a Hex Secret (no label)', !has(noise, 'Hex Secret'), types(noise));

  const labelled = Engine.scanCredentials('const api_key = "a3f5c8d9E1B2A4F6C8D0E2B4A6F8C0D2";', 't');
  check('labelled mixed-case secret accepted', has(labelled, 'API Key (labelled)'), types(labelled));

  const lowEnt = Engine.scanCredentials('api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"', 't');
  check('low-entropy labelled key rejected', !has(lowEnt, 'API Key (labelled)'), types(lowEnt));

  const emails = Engine.scanCredentials('Contact us at support@example.com', 't');
  check('email still found but severity info',
    emails.every(f => f.severity === 'info'), emails.map(f => f.severity));
}

// ---------------------------------------------------------------------------
console.log('\n[3] dedup and caps');
{
  const dup = 'ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0';
  const r = Engine.scanCredentials(dup + '\n' + dup + '\n' + dup, 't');
  check('same secret reported once', r.filter(f => f.value === dup).length === 1, r.length);

  let big = '';
  for (let i = 0; i < 500; i++) big += 'token_' + i + ' ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t' + (i % 10) + '\n';
  const capped = Engine.scanCredentials(big, 't');
  check('findings capped at MAX_FINDINGS', capped.length <= Engine.MAX_FINDINGS, capped.length);
}

// ---------------------------------------------------------------------------
console.log('\n[4] taint analysis is proximity-based');
{
  const tainted = 'const q = location.search.slice(1);\ndocument.getElementById("o").innerHTML = q;';
  const clean = 'document.getElementById("o").innerHTML = CONSTANT_TITLE;\n' + 'window.location = "/next";'.replace('window.location = "/next";', '// noop');

  const t = Engine.scanSinks(tainted, 't');
  const innerT = t.find(s => s.name === 'innerHTML assignment');
  check('nearby source marks sink tainted', innerT && innerT.hasTaintFlow === true, innerT);

  const c = Engine.scanSinks('var x = 1; el.innerHTML = fixedConstant;', 't');
  const innerC = c.find(s => s.name === 'innerHTML assignment');
  check('sink with no source nearby is untainted', innerC && innerC.hasTaintFlow === false, innerC);

  // Source 500 chars away must NOT taint
  const far = 'var a = location.search; var b = "' + 'x'.repeat(500) + '"; el.innerHTML = b;';
  const farR = Engine.scanSinks(far, 't');
  const farSink = farR.find(s => s.name === 'innerHTML assignment');
  check('source far from sink does not taint', farSink && farSink.hasTaintFlow === false, farSink && farSink.potentialSources);
}

// ---------------------------------------------------------------------------
console.log('\n[5] line numbers');
{
  const code = 'line one\nline two\nconst k = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";\nline four';
  const r = Engine.scanCredentials(code, 't');
  const tok = r.find(f => f.type === 'GitHub Token');
  check('credential line number = 3', tok && tok.line === 3, tok && tok.line);

  const kw = Engine.scanKeywords(code, ['secret', 'two']);
  const two = kw.find(k => k.keyword === 'two');
  check('keyword line number = 2', two && two.line === 2, two);

  const sinks = Engine.scanSinks('a\nb\neval(payload);', 't');
  check('sink line number = 3', sinks[0] && sinks[0].line === 3, sinks[0] && sinks[0].line);
}

// ---------------------------------------------------------------------------
console.log('\n[6] sensitive path triage');
{
  check('git dir', !!Engine.classifyPath('/.git/config'));
  check('env file', !!Engine.classifyPath('/app/.env'));
  check('backup file', !!Engine.classifyPath('/backup/db.sql'));
  check('id_rsa', !!Engine.classifyPath('/.ssh/id_rsa'));
  check('plain page is clean', Engine.classifyPath('/about') === null);
  check('admin endpoint medium',
    (Engine.classifyPath('/admin/login') || {}).severity === 'medium');

  const list = Engine.sensitivePaths(['/.git/config', '/about', '/.env', '/about']);
  check('deduped sensitive list', list.length === 2, list);
}

// ---------------------------------------------------------------------------
console.log('\n[7] keyword scan with custom list');
{
  const kw = Engine.scanKeywords('the SECRET here and api_key there', ['secret', 'api_key']);
  check('two keywords matched', kw.length >= 2, kw);
  check('regex metachars safe', Engine.scanKeywords('a.b c', ['a.b']).length >= 1);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
console.log('\n[8] hardcoded variable declarations');
{
  const r = Engine.scanHardcodedVars(
    'const apiKey = "Live-9xK2mQ7pZ4rT8vW1";\n' +
    'let normalThing = "just a value here";\n' +
    'const endpoint = "https://api.example.com";', 't');
  check('apiKey declaration found', r.some(x => x.variable === 'apiKey'), r);
  check('non-secret name skipped', !r.some(x => x.variable === 'normalThing'), r);
  check('line number present', r[0] && r[0].line === 1, r[0]);

  const skipped = Engine.scanHardcodedVars('const apiKey = "${SECRET_VAR}";', 't');
  check('template value skipped', skipped.length === 0, skipped);

  check('source map path', (Engine.classifyPath('/assets/app.js.map') || {}).severity === 'medium');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
