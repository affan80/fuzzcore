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
