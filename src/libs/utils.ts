export function isEmpty(anything?: unknown): boolean {
  if (isNullish(anything)) {
    return true;
  }
  if (typeof anything === 'object') {
    return Object.entries(anything!).length === 0;
  }
  return false;
}

export function isNullish(anything: unknown): boolean {
  return !(Boolean(anything) && anything !== null);
}

export type Optional<T, K extends keyof T> = Pick<Partial<T>, K> & Omit<T, K>;
