export function isEmpty(anyRecord?: Record<string, unknown>): boolean {
  return isNullish(anyRecord) || Object.entries(anyRecord!).length === 0;
}

export function isNullish(anything: unknown): boolean {
  return !(Boolean(anything) && anything !== null);
}
