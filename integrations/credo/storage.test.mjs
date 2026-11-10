import assert from 'node:assert/strict';
import { existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname } from 'node:path';
import { test } from 'node:test';
import { AskarStoreManager } from '@credo-ts/askar';
import { Store } from '@openwallet-foundation/askar-nodejs';
import { createTransientStore } from './storage.mjs';

async function withSession(openStore, exercise) {
  const store = await openStore();
  try {
    const session = await store.session().open();
    try {
      await exercise(session);
    } finally {
      await session.close();
    }
  } finally {
    await store.close();
  }
}

test('Credo storage retains verifier and wallet records across native pool turnover', async () => {
  const storage = createTransientStore('proofsieve-storage-regression');
  const manager = new AskarStoreManager({ dataPath: tmpdir() });
  const options = manager.getAskarStoreConfig(storage.config);
  let directory;
  const verifier = { category: 'OpenId4VcVerifierRecord', name: 'test-verifier' };
  const verifierValue = { verifierId: 'test-verifier' };
  const wallet = { category: 'OpenId4VcVerificationSessionRecord', name: 'fresh-session' };
  const walletValue = { verifierId: 'test-verifier', state: 'RequestCreated' };

  try {
    await withSession(() => Store.provision({ ...options, recreate: false }), async (session) => {
      await session.insert({ ...verifier, value: verifierValue });
    });

    // Closing the native store discards all SQLite connections without changing processes.
    await withSession(() => Store.open(options), async (session) => {
      assert.deepEqual((await session.fetch({ ...verifier, isJson: true }))?.value, verifierValue);
      await session.insert({ ...wallet, value: walletValue });
    });

    await withSession(() => Store.open(options), async (session) => {
      assert.deepEqual((await session.fetch({ ...wallet, isJson: true }))?.value, walletValue);
    });
    directory = dirname(storage.config.database.config.path);
    assert.equal(statSync(directory).mode & 0o777, 0o700);
  } finally {
    storage.dispose();
  }
  assert.equal(existsSync(directory), false, 'the process-owned database directory was removed');
});
