export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';

export type VulnerabilityStatus = 'Open' | 'In Progress' | 'Fixed' | 'False Positive' | 'Accepted Risk';

export type ScanType = 'single' | 'network' | 'domain';

export type ScanStatus = 'Queued' | 'Running' | 'Completed' | 'Failed' | 'Cancelled';

export type UserRole = 'Admin' | 'Security Analyst' | 'Read Only';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatar?: string;
  lastLogin?: string;
}

export interface Asset {
  id: string;
  ip: string;
  hostname: string;
  os: string;
  category: 'Server' | 'Workstation' | 'Network Device' | 'Web App' | 'Cloud Resource';
  status: 'Online' | 'Offline' | 'Unreachable';
  riskScore: number; // 0 - 100
  vulnerabilitiesCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  openPorts: number[];
  tags: string[];
  lastScanned: string;
}

export interface RemediationDetails {
  manualFix: string;
  detectedTargetPlatform?: string;
  bashCommands?: string[];
  powershellCommands?: string[];
  cmdCommands?: string[];
  cliCommands?: string[];
  registryChanges?: string[];
  configSnippets?: string[];
  configFilePath?: string;
  patchRecommendation?: string;
  softwareUpgrade?: string;
  verificationCommands?: string[];
  rollbackSteps?: string[];
  rebootRequired?: boolean;
  serviceRestartRequired?: string;
  estimatedImpact?: string;
}

export type FindingCategory = 'Network-Based Finding' | 'Authenticated Host Finding';

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  cvssScore: number; // 0.0 - 10.0
  cveId?: string;
  affectedHost: string;
  affectedPort?: number;
  service?: string;
  evidence: string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  businessImpact: string;
  recommendation: string;
  references: string[];
  status: VulnerabilityStatus;
  remediation: RemediationDetails;
  findingCategory?: FindingCategory;
  moduleDiscovered?: string; // Name of the scan module that discovered this finding (e.g., 'Nmap', 'Nikto', 'WhatWeb', 'SSLyze', 'DNS', 'WHOIS', 'OS Detection', 'Service Detection', 'Authenticated Windows Audit')
  aiAnalysis?: {
    executiveSummary: string;
    technicalExplanation: string;
    whyDangerous: string;
    attackScenario: string;
    businessImpact: string;
    riskPriority: string;
    stepByStepRemediation: string[];
    verificationSteps: string[];
    bestPractices: string[];
  };
  detectedAt: string;
  updatedAt?: string;
  scanId?: string;
}

export interface ModuleExecutionLog {
  moduleName: string; // e.g. 'Host Discovery', 'Nmap Port Scan', 'Service Versioning', 'OS Detection', 'Nikto Web Assessment', 'WhatWeb Tech Scan', 'SSL/TLS Assessment', 'DNS Lookup', 'WHOIS Lookup', 'Authenticated Windows Audit', 'Authenticated Linux Audit'
  status: 'Executed' | 'Skipped' | 'Failed' | 'Module unavailable';
  executed?: boolean;
  startTime?: string;
  endTime?: string;
  executionTimeMs?: number;
  exitCode?: number | string;
  reason?: string;
  commandsRun?: string[];
  hostExecutedOn?: string;
  rawOutput?: string;
  parsedSummary?: string;
  parsedResults?: string;
  findingsCount?: number;
}

export interface ScanDiagnostics {
  targetHost: string;
  isLocalHostScan: boolean;
  isWindowsServer: boolean;
  winRmConfigured: boolean;
  executionTimestamp: string;
  modulesExecuted: string[]; // List of module names executed
  modulesList: ModuleExecutionLog[];
}

export interface ScanPluginConfig {
  nmapPortScan: boolean;
  niktoWebScan: boolean;
  whatWebTechScan: boolean;
  sslAnalysis: boolean;
  dnsLookup: boolean;
  whoisLookup: boolean;
  httpHeaderScan: boolean;
  osDetection: boolean;
  serviceDetection: boolean;
}

export interface DiscoveredHost {
  ip: string;
  hostname: string;
  status: 'Up' | 'Down';
  latencyMs: number;
  openPorts: { port: number; service: string; version?: string }[];
  osGuess?: string;
}

export interface DomainInfo {
  domainName?: string;
  registeredDomain?: string;
  registry?: string;
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  lastUpdatedDate?: string;
  domainStatus?: string;
  nameServers?: string[];
  authoritativeNameServers?: string[];
  registryNameServers?: string[];
  dnssecStatus?: string;
  whoisRaw?: string;
  registrantCountry?: string;
}

export interface DnsRecordDetails {
  aRecords?: string[];
  aaaaRecords?: string[];
  mxRecords?: string[];
  nsRecords?: string[];
  txtRecords?: string[];
  spfRecord?: string;
  dmarcRecord?: string;
  dkimStatus?: string;
  cnameRecords?: string[];
  soaRecord?: string;
}

export interface IpInformation {
  publicIp?: string;
  reverseDns?: string;
  asnNumber?: string;
  ipNetworkRange?: string;
  cidr?: string;
  hostingProvider?: string;
  organization?: string;
  country?: string;
  city?: string;
  cdnDetected?: string;
}

export interface WebServerDetails {
  webServer?: string;
  framework?: string;
  programmingLanguage?: string;
  cmsDetected?: string;
  techStack?: string[];
  httpHeaders?: Record<string, string>;
  securityHeaders?: { header: string; status: 'Present' | 'Missing' | 'Insecure'; value?: string }[];
  cookieSecurity?: string;
  compression?: string;
  httpMethods?: string[];
  robotsTxt?: string;
  sitemapXml?: string;
}

export interface SslCertificateDetails {
  issuer?: string;
  subject?: string;
  san?: string[];
  expiryDate?: string;
  tlsVersions?: string[];
  weakCiphers?: string[];
  certificateChain?: string;
  hstsStatus?: string;
  ocspStatus?: string;
  heartbleedStatus?: string;
}

export interface EmailSecurityDetails {
  spfRecord?: string;
  dkimStatus?: string;
  dmarcRecord?: string;
  mxValidation?: string;
  openRelayStatus?: string;
}

export interface DomainAssessmentData {
  domainInfo?: DomainInfo;
  dnsRecords?: DnsRecordDetails;
  ipInfo?: IpInformation;
  webServer?: WebServerDetails;
  sslDetails?: SslCertificateDetails;
  emailSecurity?: EmailSecurityDetails;
}

export interface ScanResult {
  id: string;
  name: string;
  target: string;
  scanType: ScanType;
  status: ScanStatus;
  progress: number; // 0 - 100
  startTime: string;
  endTime?: string;
  durationSeconds?: number;
  riskScore: number;
  initiatedBy: string;
  pluginsUsed: ScanPluginConfig;
  discoveredHosts: DiscoveredHost[];
  vulnerabilities: Vulnerability[];
  rawOutput: {
    nmap?: string;
    nikto?: string;
    whatweb?: string;
    ssl?: string;
    dns?: string;
    whois?: string;
    httpHeader?: string;
  };
  diagnostics?: ScanDiagnostics;
  domainAssessment?: DomainAssessmentData;
  notes?: string;
}

export interface ScheduledScan {
  id: string;
  name: string;
  target: string;
  scanType: ScanType;
  frequency: 'Daily' | 'Weekly' | 'Monthly';
  nextRun: string;
  enabled: boolean;
  plugins: ScanPluginConfig;
}

export interface RemediationTask {
  id: string;
  vulnerabilityId: string;
  vulnerabilityTitle: string;
  severity: SeverityLevel;
  affectedHost: string;
  assignee: string;
  status: 'Open' | 'In Progress' | 'Under Review' | 'Resolved';
  dueDate: string;
  notes: string;
}

export interface ActivityLog {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  details: string;
  category: 'Auth' | 'Scan' | 'Vulnerability' | 'System' | 'Asset';
}

export interface DashboardStats {
  totalAssets: number;
  totalScans: number;
  activeHosts: number;
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  infoVulns: number;
  fixedVulns: number;
  openVulns: number;
  overallRiskScore: number;
  securityScore: number;
}
