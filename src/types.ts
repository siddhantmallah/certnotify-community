export type CheckName = 'ssl' | 'whois' | 'dns' | 'dnssec' | 'email' | 'headers' | 'ports' | 'blacklist' | 'uptime';

export const ALL_CHECKS: CheckName[] = ['ssl', 'whois', 'dns', 'dnssec', 'email', 'headers', 'ports', 'blacklist', 'uptime'];

/** The protocol versions older than TLS 1.2 that the legacy probe can detect. */
export type LegacyTlsVersion = 'TLSv1' | 'TLSv1.1';

export interface SSLResult {
  hostname: string;
  /**
   * The certificate is in date AND trusted (`dateValid && authorized`). Before
   * 0.5.0 this was the dates alone, so a self-signed, unknown-CA or wrong-host
   * certificate reported `valid: true`.
   */
  valid: boolean;
  /** Now is between notBefore and notAfter. The whole of what `valid` used to mean. */
  dateValid: boolean;
  /** The chain verified against Node's CA store and the certificate names this host. */
  authorized: boolean;
  /** Node's reason when `authorized` is false, e.g. `DEPTH_ZERO_SELF_SIGNED_CERT`, `ERR_TLS_CERT_ALTNAME_INVALID`. */
  authorizationError: string | null;
  /**
   * The certificate names this host, checked on its own. Node only checks the
   * name once the chain verifies, so `authorized: false` alone does not say
   * whether a self-signed certificate was also issued for the wrong name.
   */
  hostnameMatch: boolean;
  /**
   * Legacy versions the server completed (or agreed to) a handshake over,
   * oldest first. `[]` means every probe was refused by the server. `null`
   * means unknown: this runtime could not offer legacy TLS, or a probe gave no
   * answer — never read it as clean.
   */
  legacyProtocols: LegacyTlsVersion[] | null;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  issuer: { organization: string; commonName: string; country: string };
  subject: { commonName: string; altNames: string[] };
  /** The protocol a modern client negotiates, or the newest legacy one when the server speaks nothing newer. */
  tlsVersion: string;
  /**
   * From `tlsVersion` (TLS 1.3 A+, 1.2 A, 1.1 C, 1.0 D), capped at B while
   * `legacyProtocols` is non-empty — SSL Labs' convention. A legacy-only
   * server keeps its C or D. To alert on legacy TLS, read `legacyProtocols`
   * rather than inferring it from the grade.
   */
  securityGrade: string;
  serialNumber: string;
  fingerprint: string;
  keySize: number | string;
  algorithm: string;
}

export interface WhoisResult {
  domain: string;
  valid: boolean;
  error?: string;
  message?: string;
  expiryDate: string | null;
  daysRemaining: number | null;
  registrar: string;
  nameServers: string[];
  createdDate?: string | null;
  updatedDate?: string | null;
  status: string[];
}

export type DnsRecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME' | 'SOA' | 'PTR';

export interface DnsRecordResult {
  type: DnsRecordType;
  records: string[];
  error?: string;
}

export interface DnsResult {
  domain: string;
  queriedAt: string;
  results: DnsRecordResult[];
}

/**
 * `error` is a SERVFAIL from the validating resolver — usually broken DNSSEC.
 * `unknown` means the lookups themselves failed, which says nothing about the
 * domain; before 0.5.0 that case reported `unsigned`. `nonexistent` is an
 * NXDOMAIN answer: there is no such name, so nothing to be signed or not.
 */
export type DnssecStatus = 'signed-valid' | 'signed-unvalidated' | 'unsigned' | 'error' | 'unknown' | 'nonexistent';

export interface DnssecResult {
  domain: string;
  dnssecEnabled: boolean;
  dnssecValid: boolean;
  status: DnssecStatus;
  /**
   * The resolver authenticated this name's DNSKEY answer: its keys, or (for a
   * name inside a signed zone, which has none of its own) the zone's signed
   * proof that there are none. AD on the DS answer, which the parent zone
   * gives even for an unsigned delegation, no longer sets it.
   */
  adBit: boolean;
  hasDNSKEY: boolean;
  hasDS: boolean;
  nsRecords: string[];
  dnskeyCount: number;
  dsCount: number;
  rcode: { dnskey: number | null; ds: number | null };
  explanation: string;
  /** Set for `unknown` (which lookup failed) and `nonexistent` (the name does not exist). */
  error?: string;
}

export interface EmailSecurityResult {
  domain: string;
  spf: {
    /** The first published SPF record, for display. Null when none exists. */
    record: string | null;
    /** Every `v=spf1` record found. More than one is itself a fatal error. */
    records: string[];
    /** False when there is no record AND when there is more than one. */
    valid: boolean;
    mechanism: string | null;
    /** RFC 7208 forbids publishing more than one SPF record for a domain. */
    multipleRecords: boolean;
    /** Human-readable reason SPF cannot evaluate, or null when it can. */
    error: string | null;
  };
  dmarc: { record: string | null; policy: 'none' | 'quarantine' | 'reject' | null; pct: number; rua: string | null };
  dkim: { selector: string | null; record: string | null };
  score: number;
  grade: string;
  recommendations: string[];
}

export type HeaderGrade = 'good' | 'warn' | 'bad';

export interface HeaderCheckResult {
  name: string;
  present: boolean;
  value: string | null;
  grade: HeaderGrade;
  /** Counts toward `score`. False only for X-XSS-Protection, which no value can make good. */
  scored: boolean;
  description: string;
  recommendation: string | null;
}

export interface HeadersResult {
  domain: string;
  url: string;
  finalUrl: string;
  statusCode: number | null;
  score: number;
  grade: string;
  headers: HeaderCheckResult[];
  rawHeaders: Record<string, string>;
  error?: string;
}

export type PortRisk = 'low' | 'medium' | 'high' | 'critical';

export interface PortCheckResult {
  port: number;
  service: string;
  risk: PortRisk;
  open: boolean;
}

export interface PortsResult {
  domain: string;
  ip: string;
  scanned: number;
  openPorts: PortCheckResult[];
  riskLevel: PortRisk;
  results: PortCheckResult[];
}

/** `error` covers timeouts, resolver failures and the list refusing the query. It is not clean. */
export type DnsblStatus = 'listed' | 'not_listed' | 'error';

export interface BlacklistEntryResult {
  name: string;
  zone: string;
  /** Kept for 0.4 consumers: true only when `status` is `listed`. False does NOT mean clean — read `status`. */
  listed: boolean;
  status: DnsblStatus;
  /** The A records the list answered with (e.g. `127.0.0.2`), when it answered. */
  answers: string[];
  /** Why the list could not be checked, when `status` is `error`. */
  error?: string;
}

export type ReputationStatus = 'clean' | 'suspicious' | 'blacklisted';

export interface BlacklistResult {
  domain: string;
  ip: string | null;
  /**
   * `clean` covers only the lists that answered (`checkedCount`), and needs at
   * least half of the lists queried to have answered. `unknown` when fewer did
   * and none listed the address, with `error` saying how many answered. A
   * listing is reported however few answered.
   */
  reputation: ReputationStatus | 'unknown';
  listedCount: number;
  /** Lists that gave a usable answer, listed or not. */
  checkedCount: number;
  /** Lists that could not be checked. Never counted as clean. */
  errorCount: number;
  results: BlacklistEntryResult[];
  error?: string;
}

export type UptimeStatus = 'up' | 'degraded' | 'down';

export interface UptimeResult {
  domain: string;
  status: UptimeStatus;
  online: boolean;
  statusCode: number;
  statusLabel: string;
  responseTimeMs: number;
  performance: 'Excellent' | 'Good' | 'Fair' | 'Slow';
  protocol: 'https' | 'http' | 'unreachable';
  finalUrl: string | null;
  redirected: boolean;
  server: string | null;
  contentType: string | null;
}

export interface ScanReport {
  target: string;
  scannedAt: string;
  ssl?: SSLResult | { error: string };
  whois?: WhoisResult;
  dns?: DnsResult;
  dnssec?: DnssecResult;
  email?: EmailSecurityResult;
  headers?: HeadersResult;
  ports?: PortsResult | { error: string };
  blacklist?: BlacklistResult;
  uptime?: UptimeResult | { error: string };
}

// ── Phase 4: stateful checks (baseline-then-diff, backed by local state) ──

export interface DnsRecordChange {
  recordType: string;
  from: string[];
  to: string[];
  critical: boolean;
}

export interface DnsChangesResult {
  target: string;
  baseline: boolean;
  changed: boolean;
  suspicious: boolean;
  changes: DnsRecordChange[];
  checkedAt: string;
}

export interface DefacementResult {
  target: string;
  baseline: boolean;
  changed: boolean;
  hash: string;
  previousHash?: string;
  checkedAt: string;
}

export interface WhoisPrivacyContact {
  name: string | null;
  email: string | null;
  phone: string | null;
  organization: string | null;
}

export interface WhoisPrivacyResult {
  domain: string;
  baseline: boolean;
  privacyEnabled: boolean;
  privacyProvider: string | null;
  privacyChanged: boolean;
  previouslyPrivate: boolean | null;
  exposedData: WhoisPrivacyContact | null;
  checkedAt: string;
  error?: string;
}

export type MixedContentResourceType = 'image' | 'script' | 'stylesheet' | 'iframe' | 'media' | 'inline';

export interface MixedContentIssue {
  type: MixedContentResourceType;
  url: string;
  fix: string;
  firstSeenAt: string;
  occurrences: number;
}

export interface MixedContentResult {
  target: string;
  pagesScanned: number;
  issuesFound: number;
  newIssues: number;
  issues: MixedContentIssue[];
  error?: string;
  checkedAt: string;
}

export interface SubdomainCandidate {
  host: string;
  discovered: boolean;
  source: 'dns-probe' | 'ct-log';
  isNew: boolean;
}

export interface SubdomainDiscoveryResult {
  domain: string;
  scannedCandidates: number;
  discoveredCount: number;
  newCount: number;
  discovered: SubdomainCandidate[];
  ctLogQueried: boolean;
  checkedAt: string;
}
