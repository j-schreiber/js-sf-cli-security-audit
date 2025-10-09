export function isEmpty(anyRecord: Record<string, unknown>): boolean {
  return !anyRecord || Object.entries(anyRecord).length === 0;
}
