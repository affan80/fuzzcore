export type SavedCaseVersion={id:string;name:string;version:string;schema_version:string;cases:unknown[];created_at:string};
export function loadSavedCaseVersion(value:SavedCaseVersion):{text:string;authorized:false;source:string} {
 if(value.schema_version!=='declarative-v2'||!Array.isArray(value.cases)||value.cases.length<1||value.cases.length>3||!/^[a-f0-9]{64}$/.test(value.version))throw new Error('Saved case version is unsupported.');
 return {text:JSON.stringify(value.cases,null,2),authorized:false,source:`${value.name} · ${value.version.slice(0,12)}`};
}
