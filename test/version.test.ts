import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { USER_AGENT, VERSION } from '../src/version.js';

const pkg = createRequire(import.meta.url)('../package.json') as { version: string };

describe('VERSION', () => {
  it('matches package.json, so the User-Agent cannot drift from the release again', () => {
    expect(VERSION).toBe(pkg.version);
    expect(USER_AGENT).toContain(`certnotify-cli/${pkg.version} `);
  });
});
