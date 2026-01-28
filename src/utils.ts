import { createHash } from 'node:crypto';
import { isDate } from 'node:util/types';

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

export function capitalize(anyString: string): string {
  return `${anyString[0].toUpperCase()}${anyString.slice(1)}`;
}

export function uncapitalize(anyString: string): string {
  return `${anyString[0].toLowerCase()}${anyString.slice(1)}`;
}

export function isParseableDate(value: unknown): boolean {
  if (typeof value === 'string') {
    const d = new Date(value);
    return !Number.isNaN(d.getTime());
  }
  return false;
}

export function formatToLocale(value: unknown): string {
  if (isParseableDate(value)) {
    return new Date(value as string).toLocaleString();
  }
  if (isDate(value)) {
    return value.toLocaleString();
  }
  switch (typeof value) {
    case 'string':
      return value;
    case 'number':
      return value.toLocaleString();
    case 'object':
      return JSON.stringify(value);
    default:
      return '';
  }
}

export function createDigest(data: string, length: number = 8): string {
  const hash = createHash('sha256');
  hash.update(data);
  return hash.digest('hex').slice(0, length);
}

/**
 * Both dates have to be UNIX timestamps
 *
 * @param date1
 * @param date2
 */
export function differenceInDays(date1: number | string, date2: number | string): number {
  const convertedDate1 = typeof date1 === 'number' ? date1 : Date.parse(date1);
  const convertedDate2 = typeof date2 === 'number' ? date2 : Date.parse(date2);
  const diff = Math.abs(convertedDate2 - convertedDate1);
  return Math.floor(diff / (1000 * 60 * 60 * 24));
}

export type Optional<T, K extends keyof T> = Pick<Partial<T>, K> & Omit<T, K>;
