// Shared stdin reader for the detect-core JSON-contract subcommands.
// Every BYO-agent verb that takes a finding/policy reads one JSON document
// from stdin and writes one JSON document to stdout (interfaces.md §Interfaces).

export async function readStdinJson<T>(): Promise<T> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (raw.length === 0) {
    throw new Error('expected a JSON document on stdin, got empty input');
  }
  try {
    return JSON.parse(raw) as T;
  } catch (e) {
    throw new Error(`stdin is not valid JSON: ${(e as Error).message}`);
  }
}
