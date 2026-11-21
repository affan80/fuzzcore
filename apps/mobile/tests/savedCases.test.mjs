import assert from 'node:assert/strict';
import test from 'node:test';
import {loadSavedCaseVersion} from '../savedCases.ts';

test('loading a version copies its case content and never confirms or starts a scan',()=>{
 const saved={id:'saved-1',name:'Health smoke',version:'a'.repeat(64),schema_version:'declarative-v2',cases:[{path:'/health',method:'GET',params:{},expect_status:200,contains:'fixture'}],created_at:'2026-11-21'};
 const loaded=loadSavedCaseVersion(saved);assert.equal(loaded.authorized,false);assert.deepEqual(JSON.parse(loaded.text),saved.cases);
 assert.deepEqual(Object.keys(loaded).sort(),['authorized','source','text']);assert.equal(loaded.source,'Health smoke · '+saved.version.slice(0,12));
 const value=JSON.parse(loaded.text);value[0].contains='changed';assert.equal(saved.cases[0].contains,'fixture');
});

test('saved versions require supported schema, bounded cases and a valid version digest',()=>{
 const good={id:'x',name:'a',version:'b'.repeat(64),schema_version:'declarative-v2',cases:[{path:'/health'}],created_at:'2026-11-21'};
 for(const bad of [{...good,schema_version:'unknown'},{...good,cases:[]},{...good,cases:[...good.cases,...good.cases,...good.cases,...good.cases]},{...good,version:'not-a-version'}])assert.throws(()=>loadSavedCaseVersion(bad),/version/);
});
