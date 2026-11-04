// Run with: node --test internal/gui/webui/proxy_test.mjs
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';

const html = readFileSync(new URL('./static/index.html', import.meta.url), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
test('settings JavaScript parses', () => { new vm.Script(script); });
const requestSource = script.slice(script.indexOf('function proxyRequest('), script.indexOf('function renderGeneratedFields('));
function request(mode, value, profile) {
  const ctx = vm.createContext({form:{elements:{ProxyMode:{value:mode},ProxyURL:{value}},Server:{value:'https://server.example'}}});
  vm.runInContext(requestSource,ctx);
  return JSON.parse(JSON.stringify(ctx.proxyRequest(profile)));
}

test('proxy mode changes clear incompatible saved fields', () => {
  const saved = {ID:'one',HTTPSProxy:'http://alice:xxxxx@proxy:8080',NoSystemProxy:true};
  for (const mode of ['environment','direct']) {
    const body = request(mode,'socks5h://old-proxy',saved);
    assert.equal(body.HTTPSProxy,'');
    assert.equal(body.NoSystemProxy,mode === 'direct');
    assert.equal(body.KeepProxyURL,false);
    assert.equal(body.ReplaceProxyURL,false);
  }
});
test('blank saved URL is retained without resending a masked password', () => {
  const body = request('custom','',{ID:'one',HTTPSProxy:'http://alice:xxxxx@proxy:8080'});
  assert.equal(body.HTTPSProxy,'');
  assert.equal(body.KeepProxyURL,true);
  assert.equal(body.ReplaceProxyURL,false);
  assert.equal(body.NoSystemProxy,false);
});
test('a complete replacement URL is sent unchanged, including credentials', () => {
  const raw = 'socks5h://alice:p%40ss@proxy:1080';
  const body = request('custom',raw,{ID:'one',HTTPSProxy:'http://old'});
  assert.equal(body.HTTPSProxy,raw);
  assert.equal(body.KeepProxyURL,false);
  assert.equal(body.ReplaceProxyURL,true);
});
test('new profiles cannot retain nonexistent credentials', () => {
  assert.equal(request('custom','',null).KeepProxyURL,false);
});
