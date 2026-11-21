// A UI guard, not a replacement for the server's scope and identity checks.
export type LabModule = 'directories' | 'vhosts' | 'api' | 'parameters' | 'custom' | 'subdomains';
export function buildLabRequest(confirmed: boolean, modules: readonly string[] = ['directories'], customCases: unknown[] = [],directoryCases: readonly string[] = []) {
  if (confirmed !== true) throw new Error('Confirm you are authorized to test this fixed lab.');
  if (!modules.length || new Set(modules).size !== modules.length || modules.some(m => !['directories','vhosts','api','parameters','custom','subdomains'].includes(m)))
    throw new Error('Choose supported fixture modules once each.');
  if ((modules.includes('custom') && (customCases.length<1 || customCases.length>3)) || (!modules.includes('custom') && customCases.length)) throw new Error('Choose one to three declarative cases only with the custom module.');
  if(directoryCases.length>2 || new Set(directoryCases).size!==directoryCases.length || directoryCases.some(c=>!['canary-v1','upload-v1'].includes(c)) || (directoryCases.length && !modules.includes('directories')))throw new Error('Choose supported directory cases only with directories.');
  return {
    ...(directoryCases.length?{directory_cases:[...directoryCases].sort()}:{}),
    ...(modules.includes('custom')?{custom_cases:customCases}:{}),
    target_id: 'local-lab', profile_id: 'lab-small',
    modules: [...modules].sort(), authorization_confirmed: true,
  };
}

// Stateless lab-only POST. This is data, never a script or an arbitrary endpoint.
export const DISPOSABLE_POST_EXAMPLE={path:'/custom-disposable',method:'POST',params:{},body:{marker:'harmless-marker'},expect_status:200,contains:'fixture',expect_headers:{'content-type':'application/json','x-fixture-mode':'disposable'}};
