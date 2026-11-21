export type ModuleProgress={state:string;planned:number;attempted:number;completed:number;skipped?:number};
export function moduleProgressText(value:ModuleProgress|undefined):string {
 if(!value)return 'Detailed progress unavailable for this historic run.';
 return `${value.state.replaceAll('_',' ')} · ${value.completed}/${value.planned} responses completed · ${value.attempted} attempted${value.skipped?` · ${value.skipped} unused cleanup reserves`:""}`;
}
