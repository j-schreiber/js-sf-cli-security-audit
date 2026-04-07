export function chunkArray(ids: string[], chunkSize: number): string[][] {
  const chunks = [];
  for (let i = 0; i < ids.length; i += chunkSize) {
    chunks.push(ids.slice(i, i + chunkSize));
  }
  return chunks;
}

export function joinToSoqlIN(ids: string[]): string {
  return ids.map((id) => `'${id}'`).join(',');
}

export function maxDate(date1Iso?: string, date2iso?: string): string | undefined {
  if (!date1Iso) {
    return date2iso;
  }
  if (!date2iso) {
    return date1Iso;
  }
  const highestDate = Math.max(Date.parse(date1Iso), Date.parse(date2iso));
  return new Date(highestDate).toISOString();
}
