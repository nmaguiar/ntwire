// Dependency-free DOM behavior test of the actual embedded trust dialog.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const page = readFileSync(new URL('../static/index.html', import.meta.url), 'utf8');
const source = page.slice(page.indexOf('function trustModal('), page.indexOf('\n}\n', page.indexOf('function trustModal(')) + 3);
let focused;
class Element {
  constructor(tag) {this.tag = tag; this.children = []; this.style = {}; this.listeners = {}; this.textContent = '';}
  append(...nodes) {this.children.push(...nodes);}
  addEventListener(event, cb) {this.listeners[event] = cb;}
  click() {this.listeners.click?.();}
  focus() {focused = this;}
  set innerHTML(_) {throw new Error('Untrusted certificate data must use textContent');}
}
const decisions = [];
const context = vm.createContext({document: {createElement: tag => new Element(tag)}, overlay: x => x,
  answerTrust: (...args) => decisions.push(args), queueMicrotask: cb => cb()});
vm.runInContext(source, context);
const walk = node => [node, ...node.children.flatMap(walk)];
for (const changed of [false, true]) for (const metadata of [false, true]) {
  const payload = '<img src=x onerror=alert(1)>\"<script>alert(1)</script>';
  const prompt = {kind:'trust',host:payload,fingerprint:'SHA256:new',...(changed ? {previous:'SHA256:old'} : {})};
  if (metadata) {
    prompt.certificate = {subject:payload,issuer:'CN=Netskope CA',not_before:'2026-01-01',not_after:'2027-01-01',chain:[{subject:payload,issuer:'Root',sha256_fingerprint:'SHA256:root',is_ca:true}]};
    prompt.assessment = {warnings:['Possible enterprise TLS inspection']};
  }
  const modal = context.trustModal({prompt,profile:{ID:'p1',Name:'test'}});
  const nodes = walk(modal);
  const buttons = nodes.filter(n => n.tag === 'button');
  assert.deepEqual(buttons.map(b => b.textContent), ['Reject', 'Trust Certificate']);
  assert.equal(focused, buttons[0]);
  buttons[0].click(); assert.deepEqual(decisions.at(-1), ['p1',false]);
  buttons[1].click(); assert.deepEqual(decisions.at(-1), ['p1',true]);
  modal.listeners.keydown({key:'Escape',preventDefault(){}});
  assert.deepEqual(decisions.at(-1), ['p1',false]);
  assert.equal(modal.className.includes('danger'), changed);
  assert.ok(nodes.some(n => n.textContent.includes('SHA256:new')));
  if (changed) assert.ok(nodes.some(n => n.textContent.includes('SHA256:old')));
  if (metadata) {
    assert.ok(nodes.some(n => n.tag === 'details'));
    assert.ok(nodes.some(n => n.textContent === 'Subject: ' + payload));
    assert.ok(nodes.some(n => n.textContent.includes('Possible enterprise TLS inspection')));
  }
  assert.equal(nodes.some(n => n.tag === 'img' || n.tag === 'script'), false);
}
console.log('Certificate dialog: first trust, change, metadata fallback, chain, escaping, reject/trust and safe focus passed.');
