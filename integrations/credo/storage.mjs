import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function createTransientStore(id) {
  const directory = mkdtempSync(join(tmpdir(), 'proofsieve-credo-'));
  return {
    config: {
      id,
      key: randomBytes(32).toString('base64url'),
      // The database must survive retirement of every SQLite pool connection.
      database: { type: 'sqlite', config: { path: join(directory, 'wallet.db') } },
    },
    dispose: () => rmSync(directory, { recursive: true, force: true }),
  };
}
