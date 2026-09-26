import { describe, it, expect } from 'vitest';
import { describeError } from '../src/errors.js';

/**
 * A failure that cannot say why it failed.
 *
 * `${error.message}` is the obvious thing to write and it has a hole in it:
 * when a hostname resolves to several addresses and all of them fail, Node
 * raises an `AggregateError` whose `message` is the empty string, with the
 * real causes in `.errors`. The scanner then reported
 * `"SSL check failed: "` — CertNotify recorded exactly that against a live
 * host on 2026-09-26, and the record was useless.
 *
 * It survived local testing because the same host produces a populated
 * message on a single-stack machine. Only dual-stack resolution triggers it.
 */

const aggregate = (...codes: string[]) => {
  const err = new AggregateError(
    codes.map((code) => Object.assign(new Error(`connect ${code} 1.2.3.4:443`), { code })),
  );
  // Node leaves this empty — the entire point.
  expect(err.message).toBe('');
  return err;
};

describe('describeError', () => {
  it('reports the causes of an AggregateError whose own message is empty', () => {
    expect(describeError(aggregate('ECONNREFUSED'))).toContain('ECONNREFUSED');
  });

  it('de-duplicates identical causes', () => {
    // Four addresses refusing gives four identical causes; repeating the same
    // string four times is noise, not information.
    const out = describeError(aggregate('ECONNREFUSED', 'ECONNREFUSED', 'ECONNREFUSED'));
    expect(out.match(/ECONNREFUSED/g)).toHaveLength(1);
  });

  it('keeps distinct causes, because they are different facts', () => {
    const out = describeError(aggregate('ECONNREFUSED', 'EHOSTUNREACH'));
    expect(out).toContain('ECONNREFUSED');
    expect(out).toContain('EHOSTUNREACH');
  });

  it('falls back to the code when an Error carries no message', () => {
    expect(describeError(Object.assign(new Error(''), { code: 'ETIMEDOUT' }))).toBe('ETIMEDOUT');
  });

  it('uses the message when there is one', () => {
    expect(describeError(new Error('certificate has expired'))).toBe('certificate has expired');
  });

  it.each([
    [null, 'null'],
    [undefined, 'undefined'],
    ['plain string', 'plain string'],
  ])('handles %s thrown directly', (thrown, expected) => {
    expect(describeError(thrown)).toBe(expected);
  });

  it('never returns an empty string, whatever it is given', () => {
    const nasties: unknown[] = [
      new Error(''),
      new AggregateError([]),
      {},
      0,
      false,
      Symbol('x'),
      { toString() { throw new Error('hostile'); } },
    ];
    for (const value of nasties) {
      const out = describeError(value);
      expect(out.length, `empty for ${String(out)}`).toBeGreaterThan(0);
    }
  });

  it('clips a pathological message rather than storing all of it', () => {
    expect(describeError(new Error('x'.repeat(5000))).length).toBeLessThanOrEqual(200);
  });
});
