// Kept in step with package.json by test/version.test.ts. Reading package.json
// at runtime would need import.meta.url, which the CommonJS build lacks.
export const VERSION = '0.5.0';

export const USER_AGENT = `certnotify-cli/${VERSION} (+https://www.certnotify.com)`;
