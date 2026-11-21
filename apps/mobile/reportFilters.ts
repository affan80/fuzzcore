export const FILTER_VALUES={severity:['high','medium','low','informational'],module:['directories','vhosts','api','parameters','custom','subdomains'],confidence:['fixture-confirmed','observed','signal'],review_state:['open','acknowledged','retest_requested','fixed']} as const;
export type ReportFilters=Partial<Record<keyof typeof FILTER_VALUES,string>>;
export function reportQuery(filters:ReportFilters):string {
 if(Object.keys(filters).some(key=>!(key in FILTER_VALUES)))throw new Error('Unsupported report filter.');
 const values:string[]=[];
 for(const key of Object.keys(FILTER_VALUES) as (keyof typeof FILTER_VALUES)[]){const value=filters[key];if(value===undefined)continue;if(!(FILTER_VALUES[key] as readonly string[]).includes(value))throw new Error('Unsupported report filter.');values.push(`${key}=${encodeURIComponent(value)}`);}
 return values.length?'?'+values.join('&'):'';
}
export function fixedReviewRequest(note:string,retestId:string){
 if(!note.trim()||note.length>500)throw new Error('Enter a manual review note, maximum 500 characters.');
 if(!retestId.trim()||retestId.length>64)throw new Error('Enter the completed same-scope linked retest ID.');
 return {state:'fixed',note:note.trim(),retest_scan_id:retestId.trim()};
}
