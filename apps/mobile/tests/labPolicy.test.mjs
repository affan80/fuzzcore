import assert from 'node:assert/strict';
import test from 'node:test';
import { buildLabRequest } from '../labPolicy.ts';

test('no scan can start without an explicit authorization confirmation', () => {
  assert.throws(() => buildLabRequest(false), /Confirm/);
});

test('confirmed requests contain only the fixed approved lab and supported module', () => {
  assert.deepEqual(buildLabRequest(true), {
    target_id: 'local-lab', profile_id: 'lab-small',
    modules: ['directories'], authorization_confirmed: true,
  });
});

test('confirmed module choices are explicit, unique and limited to fixture implementations', () => {
  assert.deepEqual(buildLabRequest(true, ['vhosts']).modules, ['vhosts']);
  assert.deepEqual(buildLabRequest(true, ['directories','vhosts']).modules, ['directories','vhosts']);
  for (const modules of [[],['unknown'],['vhosts','vhosts']]) {
    assert.throws(() => buildLabRequest(true, modules), /module/);
  }
});

test('API fixture module is a bounded supported choice', () => {
  assert.deepEqual(buildLabRequest(true, ['api']).modules, ['api']);
  assert.deepEqual(buildLabRequest(true, ['directories','api','vhosts']).modules, ['api','directories','vhosts']);
});

test('parameter signals stay inside the fixed fixture module list', () => {
  assert.deepEqual(buildLabRequest(true,['parameters']).modules,['parameters']);
  assert.throws(()=>buildLabRequest(true,['unknown']),/module/);
});

test('custom case selection needs bounded declarative cases', () => {
  const cases=[{path:'/health',method:'GET',params:{},expect_status:200,contains:'fixture'}];
  assert.deepEqual(buildLabRequest(true,['custom'],cases).custom_cases,cases);
  assert.throws(()=>buildLabRequest(true,['custom'],[]),/case/);
  assert.throws(()=>buildLabRequest(true,['custom'],[...cases,...cases,...cases,...cases]),/case/);
});

test('DNS fixture discovery is explicit and does not supply HTTP targets', () => {
  assert.deepEqual(buildLabRequest(true,['subdomains']).modules,['subdomains']);
  assert.equal(buildLabRequest(true,['subdomains']).target_id,'local-lab');
});

test('named disposable POST example keeps its bounded body and header expectations',async()=>{
 const {DISPOSABLE_POST_EXAMPLE}=await import('../labPolicy.ts');
 assert.equal(DISPOSABLE_POST_EXAMPLE.method,'POST');
 assert.equal(DISPOSABLE_POST_EXAMPLE.path,'/custom-disposable');
 assert.deepEqual(Object.keys(DISPOSABLE_POST_EXAMPLE.body),['marker']);
 assert.deepEqual(Object.keys(DISPOSABLE_POST_EXAMPLE.expect_headers),['content-type','x-fixture-mode']);
 assert.deepEqual(buildLabRequest(true,['custom'],[DISPOSABLE_POST_EXAMPLE]).custom_cases,[DISPOSABLE_POST_EXAMPLE]);
 assert.throws(()=>buildLabRequest(false,['custom'],[DISPOSABLE_POST_EXAMPLE]),/Confirm/);
});

test('synthetic canary is explicit and adds only its named case selection',()=>{
 const row=buildLabRequest(true,['directories'],[],['canary-v1']);
 assert.deepEqual(row.directory_cases,['canary-v1']);
 assert.equal(buildLabRequest(true,['directories']).directory_cases,undefined);
 for(const modules of [['vhosts'],['custom']])assert.throws(()=>buildLabRequest(true,modules,[],['canary-v1']),/case|directories/);
 assert.throws(()=>buildLabRequest(true,['directories'],[],['upload-v1']),/case/);
 assert.throws(()=>buildLabRequest(false,['directories'],[],['canary-v1']),/Confirm/);
});
