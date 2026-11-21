import assert from 'node:assert/strict';
import test from 'node:test';
import {moduleProgressText} from '../moduleProgress.ts';

test('module progress distinguishes attempted requests from completed responses',()=>{
 assert.equal(moduleProgressText({state:'running',planned:4,attempted:2,completed:1}),'running · 1/4 responses completed · 2 attempted');
 assert.equal(moduleProgressText({state:'completed',planned:3,attempted:3,completed:3}),'completed · 3/3 responses completed · 3 attempted');
});
test('cancelled and unstarted modules are not displayed as completed',()=>{
 assert.equal(moduleProgressText({state:'cancelled',planned:4,attempted:1,completed:1}),'cancelled · 1/4 responses completed · 1 attempted');
 assert.equal(moduleProgressText({state:'not_run',planned:3,attempted:0,completed:0}),'not run · 0/3 responses completed · 0 attempted');
});
test('missing historic progress is shown as unavailable rather than inferred',()=>{
 assert.equal(moduleProgressText(undefined),'Detailed progress unavailable for this historic run.');
});


test('unused cleanup recovery requests are skipped, never reported as responses',()=>{
 assert.equal(moduleProgressText({state:'completed',planned:10,attempted:8,completed:8,skipped:2}),'completed · 8/10 responses completed · 8 attempted · 2 unused cleanup reserves');
});
