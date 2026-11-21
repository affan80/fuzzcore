// A UI guard, not a replacement for the server's scope and identity checks.
export type LabModule = 'directories' | 'vhosts' | 'api' | 'parameters' | 'custom' | 'subdomains';
export function buildLabRequest(confirmed: boolean, modules: readonly string[] = ['directories'], customCases: unknown[] = []) {
  if (confirmed !== true) throw new Error('Confirm you are authorized to test this fixed lab.');
  if (!modules.length || new Set(modules).size !== modules.length || modules.some(m => !['directories','vhosts','api','parameters','custom','subdomains'].includes(m)))
    throw new Error('Choose supported fixture modules once each.');
  if ((modules.includes('custom') && (customCases.length<1 || customCases.length>3)) || (!modules.includes('custom') && customCases.length)) throw new Error('Choose one to three declarative cases only with the custom module.');
  return {
    ...(modules.includes('custom')?{custom_cases:customCases}:{}),
    target_id: 'local-lab', profile_id: 'lab-small',
    modules: [...modules].sort(), authorization_confirmed: true,
  };
}
