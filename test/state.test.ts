import { describe, it, expect, afterEach } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { readState, writeState } from '../src/state.js';

let tmpDirs: string[] = [];

async function tempStateDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'certnotify-state-test-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tmpDirs.map((d) => fs.rm(d, { recursive: true, force: true }).catch(() => {})));
  tmpDirs = [];
});

describe('readState / writeState', () => {
  it('returns an empty object when no state file exists yet', async () => {
    const stateDir = await tempStateDir();
    const state = await readState('example.com', { stateDir });
    expect(state).toEqual({});
  });

  it('round-trips a written state object', async () => {
    const stateDir = await tempStateDir();
    await writeState('example.com', { dns: { records: { A: ['1.2.3.4'] } } }, { stateDir });
    const state = await readState('example.com', { stateDir });
    expect(state.dns.records.A).toEqual(['1.2.3.4']);
  });

  it('keeps state for different targets separate', async () => {
    const stateDir = await tempStateDir();
    await writeState('a.com', { marker: 'a' }, { stateDir });
    await writeState('b.com', { marker: 'b' }, { stateDir });
    expect((await readState('a.com', { stateDir })).marker).toBe('a');
    expect((await readState('b.com', { stateDir })).marker).toBe('b');
  });

  it('sanitizes targets with characters unsafe for filenames', async () => {
    const stateDir = await tempStateDir();
    await writeState('https://weird:target/path', { ok: true }, { stateDir });
    const files = await fs.readdir(stateDir);
    expect(files).toHaveLength(1);
    expect(files[0]).not.toMatch(/[:/]/);
  });
});
