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
