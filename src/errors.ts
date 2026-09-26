/**
 * Turning a thrown value into something that says what went wrong.
 *
 * `${error.message}` looks safe and is not. When a hostname resolves to more
 * than one address and every connection fails, Node raises an
 * **`AggregateError` whose `message` is the empty string** — the real causes
 * live in `.errors`. Interpolating `.message` then produces
 * `"SSL check failed: "`, a failure that reports nothing about itself.
 *
 * That is not hypothetical. CertNotify recorded exactly that string against a
 * real host on 2026-09-26: the domain refused TLS on both its A and AAAA
 * records, so the check genuinely failed, and the record of it was useless.
 * The same host reproduced with a populated message on a single-stack machine,
 * which is why it survived local testing.
 *
 * A thrown value may also be a plain `Error` with an empty message, or not an
 * `Error` at all. This never returns an empty string.
 */

/** Longest single cause kept, so one pathological message cannot fill a column. */
const MAX_CAUSE = 200;

function clip(text: string): string {
  return text.length > MAX_CAUSE ? `${text.slice(0, MAX_CAUSE - 1)}…` : text;
}

function isAggregate(error: unknown): error is AggregateError {
  return (
    error instanceof Error &&
    'errors' in error &&
    Array.isArray((error as { errors?: unknown }).errors)
  );
}

/**
 * A human-readable cause for any thrown value.
 *
 * Prefers, in order: the aggregated causes, the message, the syscall code, the
 * error name. The code is worth reaching for even when a message exists on
 * some paths, but a message is more specific when present, so it wins.
 */
export function describeError(error: unknown): string {
  if (isAggregate(error)) {
    // De-duplicated: four addresses refusing gives four identical causes, and
    // "ECONNREFUSED" reads better than "ECONNREFUSED, ECONNREFUSED, …".
    const causes = [...new Set(error.errors.map((inner) => describeError(inner)))];
    if (causes.length > 0) return clip(causes.join('; '));
  }

  if (error instanceof Error) {
    if (error.message) return clip(error.message);

    // An Error with no message still carries identity worth recording.
    const code = (error as NodeJS.ErrnoException).code;
    if (code) return clip(String(code));
    if (error.name && error.name !== 'Error') return clip(error.name);
    return 'Unknown error';
  }

  if (error === null) return 'null';
  if (error === undefined) return 'undefined';

  // `String(value)` can itself throw — a Symbol, or an object whose toString
  // is hostile. A diagnostic helper must not become the failure.
  try {
    const text = typeof error === 'string' ? error : JSON.stringify(error) ?? String(error);
    return clip(text || 'Unknown error');
  } catch {
    return 'Unserialisable error';
  }
}
