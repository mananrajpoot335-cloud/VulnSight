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
  moduleName: string; // e.g. 'Host Discovery', 'Port Scan', 'Service Detection', 'OS Detection', 'Web Assessment', 'SSL Assessment', 'Authenticated Windows Audit', 'Authenticated Linux Audit'
  status: 'Executed' | 'Skipped' | 'Failed';
  reason?: string;
  commandsRun?: string[];
  hostExecutedOn?: string;
  rawOutput?: string;
  parsedSummary?: string;
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
