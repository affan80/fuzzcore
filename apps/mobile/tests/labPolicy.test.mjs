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
  for (const modules of [[],['subdomains'],['vhosts','vhosts']]) {
    assert.throws(() => buildLabRequest(true, modules), /module/);
  }
});

test('API fixture module is a bounded supported choice', () => {
  assert.deepEqual(buildLabRequest(true, ['api']).modules, ['api']);
  assert.deepEqual(buildLabRequest(true, ['directories','api','vhosts']).modules, ['api','directories','vhosts']);
});
