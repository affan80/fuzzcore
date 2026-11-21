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
