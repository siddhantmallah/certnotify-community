export type CheckName = 'ssl' | 'whois' | 'dns' | 'dnssec' | 'email' | 'headers' | 'ports' | 'blacklist';

export const ALL_CHECKS: CheckName[] = ['ssl', 'whois', 'dns', 'dnssec', 'email', 'headers', 'ports', 'blacklist'];

export interface SSLResult {
  hostname: string;
  valid: boolean;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  issuer: { organization: string; commonName: string; country: string };
  subject: { commonName: string; altNames: string[] };
  tlsVersion: string;
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

export type DnssecStatus = 'signed-valid' | 'signed-unvalidated' | 'unsigned' | 'error';

export interface DnssecResult {
  domain: string;
  dnssecEnabled: boolean;
  dnssecValid: boolean;
  status: DnssecStatus;
  adBit: boolean;
  hasDNSKEY: boolean;
  hasDS: boolean;
  nsRecords: string[];
  dnskeyCount: number;
  dsCount: number;
  explanation: string;
  error?: string;
}

export interface EmailSecurityResult {
  domain: string;
  spf: { record: string | null; valid: boolean; mechanism: string | null };
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

export interface BlacklistEntryResult {
  name: string;
  zone: string;
  listed: boolean;
}

export type ReputationStatus = 'clean' | 'suspicious' | 'blacklisted';

export interface BlacklistResult {
  domain: string;
  ip: string | null;
  reputation: ReputationStatus | 'unknown';
  listedCount: number;
  results: BlacklistEntryResult[];
  error?: string;
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
}
