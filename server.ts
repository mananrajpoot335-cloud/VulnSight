import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini Client server-side
const getGeminiClient = () => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    return null;
  }
  return new GoogleGenAI({
    apiKey: apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
};

// Simulated Database in-memory state for initial runtime
let mockScans = [
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
    vulnerabilities: [
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
        detectedAt: '2026-07-22T18:32:10Z',
        scanId: 'scn-1001'
      }
    ],
    rawOutput: {
      nmap: 'Starting Nmap 7.94 ( https://nmap.org ) at 2026-07-22 18:25 UTC\nNmap scan report for 192.168.1.15\nHost is up (0.0014s latency).\nPORT 443/tcp open ssl/http\n| ssl-heartbleed: VULNERABLE',
      nikto: '- Nikto v2.5.0\n+ Target IP: 192.168.1.15\n+ OpenSSL/1.0.1e appears to be outdated and vulnerable to CVE-2014-0160.',
      whatweb: 'http://192.168.1.15 [200 OK] Nginx[1.18.0], OpenSSL[1.0.1e]',
      ssl: 'Issuer: CN=VulnSight Dev CA\nVulnerable to Heartbleed extension over-read: YES'
    },
    notes: 'Routine security assessment of core production database server.'
  }
];

// Health Check API
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// AI Vulnerability Analysis Proxy Endpoint
app.post('/api/ai-analyze', async (req, res) => {
  try {
    const { vulnerability } = req.body;
    if (!vulnerability) {
      return res.status(400).json({ error: 'Vulnerability object is required.' });
    }

    const ai = getGeminiClient();

    if (!ai) {
      // Fallback response if GEMINI_API_KEY is not supplied
      return res.json({
        executiveSummary: `[Rule-based AI Summary] ${vulnerability.title} represents a critical security risk on host ${vulnerability.affectedHost}. Immediate remediation is strongly recommended.`,
        technicalExplanation: `The service on ${vulnerability.affectedHost}:${vulnerability.affectedPort || 'N/A'} (${vulnerability.service || 'Unknown'}) exhibits signature traits for ${vulnerability.cveId || 'known vulnerability'}.`,
        whyDangerous: 'Exposes system memory, authentication cookies, or operational state to unauthorized remote network actors without requiring privilege credentials.',
        attackScenario: `An attacker crafts targeted packets to ${vulnerability.affectedHost} on port ${vulnerability.affectedPort || 80}, capturing internal state and leveraging findings for secondary exploitation.`,
        businessImpact: 'Risk of confidential data exposure, regulatory non-compliance fines, and reputational brand damage.',
        riskPriority: vulnerability.severity === 'Critical' ? 'P1 - Immediate (Within 24 Hours)' : 'P2 - High (Within 7 Days)',
        stepByStepRemediation: [
          `Review network exposure for host ${vulnerability.affectedHost}`,
          `Execute system updates for packages controlling ${vulnerability.service || 'service'}`,
          'Validate non-vulnerability status using Nmap or security regression test suites',
          'Document patch completion in the VulnSight audit log'
        ],
        verificationSteps: [
          `Run verification command: ${vulnerability.remediation?.verificationCommands?.[0] || 'nmap -sV -p ' + (vulnerability.affectedPort || 80) + ' ' + vulnerability.affectedHost}`,
          'Check application log streams for zero abnormal error signatures'
        ],
        bestPractices: [
          'Enable automated package security updates',
          'Enforce strict ingress firewall rules blocking unused ports',
          'Deploy Web Application Firewall (WAF) policies for public endpoints'
        ]
      });
    }

    const prompt = `You are an expert cybersecurity vulnerability analyst. Analyze this security finding and generate a detailed report in simple, clear English.

Vulnerability Title: ${vulnerability.title}
Severity: ${vulnerability.severity} (CVSS ${vulnerability.cvssScore})
CVE: ${vulnerability.cveId || 'N/A'}
Affected Host: ${vulnerability.affectedHost} (Port: ${vulnerability.affectedPort || 'N/A'})
Service: ${vulnerability.service || 'N/A'}
Description: ${vulnerability.description}
Evidence: ${vulnerability.evidence}

Respond strictly in valid JSON matching this structure:
{
  "executiveSummary": "1-2 concise sentences for management",
  "technicalExplanation": "Detailed technical mechanism of the flaw",
  "whyDangerous": "Clear explanation of why this flaw poses extreme danger",
  "attackScenario": "Realistic step-by-step attacker scenario",
  "businessImpact": "Potential operational, financial, or regulatory impact",
  "riskPriority": "e.g., P1 - Immediate / P2 - High Priority",
  "stepByStepRemediation": ["Step 1...", "Step 2..."],
  "verificationSteps": ["Verification 1...", "Verification 2..."],
  "bestPractices": ["Best practice 1...", "Best practice 2..."]
}`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.6-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
      },
    });

    const parsedText = response.text || '{}';
    const jsonOutput = JSON.parse(parsedText);
    res.json(jsonOutput);
  } catch (err: any) {
    console.error('Error in AI analysis endpoint:', err);
    res.status(500).json({ error: 'Failed to generate AI analysis: ' + (err.message || 'Unknown error') });
  }
});

// Launch Scan Engine Simulation API
app.post('/api/scans/launch', async (req, res) => {
  const { target, scanType, name, plugins } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: 'Target IP, Subnet, or Domain is required.' });
  }

  const scanId = 'scn-' + Date.now().toString().slice(-6);
  const now = new Date().toISOString();

  // Generate synthetic discovered hosts and findings based on target type
  let discoveredHosts = [];
  let vulnerabilities = [];
  let riskScore = 45;

  if (scanType === 'network' || target.includes('/')) {
    discoveredHosts = [
      {
        ip: target.replace(/\/.*$/, '') + '.1',
        hostname: 'gateway-router.local',
        status: 'Up',
        latencyMs: 1.1,
        openPorts: [{ port: 22, service: 'ssh', version: 'OpenSSH 8.9' }, { port: 80, service: 'http', version: 'lighttpd 1.4' }]
      },
      {
        ip: target.replace(/\/.*$/, '') + '.15',
        hostname: 'web-srv-01.internal',
        status: 'Up',
        latencyMs: 2.3,
        openPorts: [{ port: 80, service: 'http', version: 'Nginx 1.18' }, { port: 443, service: 'https', version: 'OpenSSL 1.0.1e' }, { port: 8080, service: 'http-alt', version: 'Apache Tomcat 9.0' }]
      },
      {
        ip: target.replace(/\/.*$/, '') + '.88',
        hostname: 'nas-storage.internal',
        status: 'Up',
        latencyMs: 1.8,
        openPorts: [{ port: 445, service: 'microsoft-ds', version: 'Samba 4.15' }, { port: 2049, service: 'nfs' }]
      }
    ];
    riskScore = 82;
    vulnerabilities = [
      {
        id: `vuln-${Date.now()}-1`,
        title: 'Deprecated SSL/TLS Protocol Support (TLS 1.0 / 1.1 Enabled)',
        description: 'The remote web server accepts incoming connections encrypted with TLS 1.0 and TLS 1.1 protocols, which are deprecated due to cryptographic weaknesses.',
        severity: 'Medium',
        cvssScore: 6.1,
        cveId: 'CVE-2011-3389',
        affectedHost: target.replace(/\/.*$/, '') + '.15',
        affectedPort: 443,
        service: 'https (Nginx)',
        evidence: 'Handshake completed successfully with cipher TLS_RSA_WITH_AES_128_CBC_SHA under protocol TLSv1.0.',
        riskLevel: 'Medium',
        businessImpact: 'Exposes encrypted session communications to man-in-the-middle decryption (BEAST attack vector).',
        recommendation: 'Disable TLS 1.0 and 1.1 protocols in web server configuration; restrict ciphers to TLS 1.2 and TLS 1.3.',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2011-3389'],
        status: 'Open',
        remediation: {
          manualFix: 'Configure ssl_protocols directive in Nginx or Apache config to disable legacy TLS versions.',
          bashCommands: [
            'sudo sed -i "s/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3;/" /etc/nginx/nginx.conf',
            'sudo nginx -t && sudo systemctl reload nginx'
          ],
          configSnippets: [
            'ssl_protocols TLSv1.2 TLSv1.3;',
            'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;'
          ],
          verificationCommands: [
            'nmap --script ssl-enum-ciphers -p 443 ' + target.replace(/\/.*$/, '') + '.15'
          ]
        },
        detectedAt: now,
        scanId: scanId
      }
    ];
  } else if (scanType === 'domain' || target.includes('.')) {
    discoveredHosts = [
      {
        ip: '93.184.216.34',
        hostname: target,
        status: 'Up',
        latencyMs: 18.5,
        openPorts: [{ port: 80, service: 'http', version: 'Cloudflare / Nginx' }, { port: 443, service: 'https', version: 'TLS 1.3' }]
      }
    ];
    riskScore = 52;
    vulnerabilities = [
      {
        id: `vuln-${Date.now()}-2`,
        title: 'Missing Cross-Origin Resource Sharing (CORS) Wildcard Restriction',
        description: 'The web application sends Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true on sensitive REST endpoints.',
        severity: 'High',
        cvssScore: 7.5,
        cveId: 'CVE-2020-13110',
        affectedHost: target,
        affectedPort: 443,
        service: 'https (REST API)',
        evidence: 'HTTP GET request with header `Origin: https://malicious-domain.com` returned `Access-Control-Allow-Origin: https://malicious-domain.com`.',
        riskLevel: 'High',
        businessImpact: 'Third-party malicious sites visited by authenticated users can execute background API calls and steal user data.',
        recommendation: 'Whitelist explicitly trusted origins rather than dynamically reflecting the incoming Origin header.',
        references: ['https://owasp.org/www-community/attacks/CORS_Origin_Header_Scrutiny'],
        status: 'Open',
        remediation: {
          manualFix: 'Update CORS middleware configuration in web application framework.',
          configSnippets: [
            '// Express JS Example:',
            'app.use(cors({ origin: ["https://app.example.com"], credentials: true }));'
          ],
          verificationCommands: [
            `curl -H "Origin: https://evil.com" -I -k https://${target}/api/user`
          ]
        },
        detectedAt: now,
        scanId: scanId
      }
    ];
  } else {
    // Single IP target
    discoveredHosts = [
      {
        ip: target,
        hostname: `host-${target.replace(/\./g, '-')}.local`,
        status: 'Up',
        latencyMs: 1.2,
        openPorts: [
          { port: 22, service: 'ssh', version: 'OpenSSH 8.9p1' },
          { port: 80, service: 'http', version: 'Apache 2.4.52' },
          { port: 443, service: 'https', version: 'OpenSSL 1.1.1t' },
          { port: 3306, service: 'mysql', version: 'MySQL 8.0.32' }
        ],
        osGuess: 'Linux 5.x / Ubuntu 22.04'
      }
    ];
    riskScore = 68;
    vulnerabilities = [
      {
        id: `vuln-${Date.now()}-3`,
        title: 'Apache HTTP Server Path Traversal & File Disclosure',
        description: 'A flaw in path normalization in Apache HTTP Server 2.4.49 / 2.4.50 allows unauthenticated attackers to map URLs to files outside the document root.',
        severity: 'High',
        cvssScore: 8.6,
        cveId: 'CVE-2021-41773',
        affectedHost: target,
        affectedPort: 80,
        service: 'http (Apache 2.4.52)',
        evidence: 'GET /icons/.%2e/.%2e/.%2e/.%2e/etc/passwd returned system account credentials snippet.',
        riskLevel: 'High',
        businessImpact: 'Arbitrary file read on host web server leading to configuration and credential leakage.',
        recommendation: 'Upgrade Apache HTTP Server to version 2.4.51 or later.',
        references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773'],
        status: 'Open',
        remediation: {
          manualFix: 'Upgrade apache2 package or update httpd.conf to ensure Require all denied on root directory.',
          bashCommands: [
            'sudo apt update && sudo apt install --only-upgrade apache2',
            'apache2 -v'
          ],
          verificationCommands: [
            `curl -s --path-as-is "http://${target}/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"`
          ]
        },
        detectedAt: now,
        scanId: scanId
      }
    ];
  }

  const newScan = {
    id: scanId,
    name: name || `${scanType.toUpperCase()} Scan - ${target}`,
    target,
    scanType,
    status: 'Completed',
    progress: 100,
    startTime: now,
    endTime: new Date(Date.now() + 180000).toISOString(),
    durationSeconds: 180,
    riskScore,
    initiatedBy: 'admin@vulnsight.local',
    pluginsUsed: plugins || {
      nmapPortScan: true,
      niktoWebScan: true,
      whatWebTechScan: true,
      sslAnalysis: true,
      dnsLookup: true,
      whoisLookup: true,
      httpHeaderScan: true,
      osDetection: true,
      serviceDetection: true
    },
    discoveredHosts,
    vulnerabilities,
    rawOutput: {
      nmap: `Starting Nmap 7.94 for target ${target}...\nDiscovered ${discoveredHosts.length} active hosts.\nService scan complete.`,
      nikto: `Nikto v2.5.0 target ${target}: Analysis completed with ${vulnerabilities.length} vulnerabilities detected.`,
      whatweb: `WhatWeb technology fingerprint complete for target ${target}.`,
      ssl: `SSL/TLS protocol cipher audit completed.`
    },
    notes: `Scan launched via VulnSight web console against target ${target}`
  };

  mockScans.unshift(newScan);
  res.json(newScan);
});

// Vite Middleware for Dev or Static files for Production
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`VulnSight server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
