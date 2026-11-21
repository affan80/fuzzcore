import test from 'node:test';import assert from 'node:assert/strict';
import {reportQuery,fixedReviewRequest} from '../reportFilters.ts';

test('filter queries are deterministic and restricted to supported fields and values',()=>{
 assert.equal(reportQuery({}),'');assert.equal(reportQuery({module:'api',severity:'high'}),'?severity=high&module=api');
 assert.equal(reportQuery({review_state:'fixed',confidence:'observed'}),'?confidence=observed&review_state=fixed');
 assert.throws(()=>reportQuery({module:'outside'}),/filter/);assert.throws(()=>reportQuery({extra:'secret'}),/filter/);
});

test('fixed is an explicit manual review request, never an automatic comparison outcome',()=>{
 assert.throws(()=>fixedReviewRequest('', 'linked-retest-id'),/note/);assert.throws(()=>fixedReviewRequest('reviewed', ''),/retest/);
 assert.deepEqual(fixedReviewRequest('Manual fixture change reviewed','linked-retest-id'),{state:'fixed',note:'Manual fixture change reviewed',retest_scan_id:'linked-retest-id'});
});
