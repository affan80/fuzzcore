// A UI guard, not a replacement for the server's scope and identity checks.
export function buildLabRequest(confirmed: boolean) {
  if (confirmed !== true) throw new Error('Confirm you are authorized to test this fixed lab.');
  return {
    target_id: 'local-lab', profile_id: 'lab-small',
    modules: ['directories'], authorization_confirmed: true,
  };
}
