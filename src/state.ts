import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export interface StateOptions {
  /** Override where baseline state is stored. Defaults to ~/.certnotify/state. */
  stateDir?: string;
}

/**
 * Local baseline storage for stateful checks (DNS changes, defacement,
 * WHOIS privacy, mixed content, subdomain discovery) — one JSON file per
 * scanned target, so a second run can detect what changed since the first.
 *
 * Defaults to the home directory (not the current working directory) so a
 * cron job or CI runner invoked from varying working directories doesn't
 * see a spuriously "fresh" baseline every time.
 */

export function defaultStateDir(): string {
  return path.join(os.homedir(), '.certnotify', 'state');
}

function sanitizeTarget(target: string): string {
  return target.replace(/[^a-zA-Z0-9.-]/g, '_');
}

function stateFilePath(target: string, opts: StateOptions = {}): string {
  const dir = opts.stateDir ?? defaultStateDir();
  return path.join(dir, `${sanitizeTarget(target)}.json`);
}

export async function readState(target: string, opts: StateOptions = {}): Promise<Record<string, any>> {
  try {
    const raw = await fs.readFile(stateFilePath(target, opts), 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

export async function writeState(target: string, data: Record<string, any>, opts: StateOptions = {}): Promise<void> {
  const dir = opts.stateDir ?? defaultStateDir();
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(stateFilePath(target, opts), JSON.stringify(data, null, 2), 'utf-8');
}
