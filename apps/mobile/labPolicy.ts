// A UI guard, not a replacement for the server's scope and identity checks.
export type LabModule = 'directories' | 'vhosts' | 'api' | 'parameters';
export function buildLabRequest(confirmed: boolean, modules: readonly string[] = ['directories']) {
  if (confirmed !== true) throw new Error('Confirm you are authorized to test this fixed lab.');
  if (!modules.length || new Set(modules).size !== modules.length || modules.some(m => !['directories','vhosts','api','parameters'].includes(m)))
    throw new Error('Choose supported fixture modules once each.');
  return {
    target_id: 'local-lab', profile_id: 'lab-small',
    modules: [...modules].sort(), authorization_confirmed: true,
  };
}
