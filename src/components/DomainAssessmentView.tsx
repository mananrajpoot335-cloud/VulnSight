import React from 'react';
import { 
  Globe, Server, Shield, Mail, Lock, Cpu, FileText, CheckCircle2, XCircle, AlertTriangle, Layers, Activity, Search
} from 'lucide-react';
import { ScanResult, DomainAssessmentData } from '../types';

interface DomainAssessmentViewProps {
  scan: ScanResult;
}

export const DomainAssessmentView: React.FC<DomainAssessmentViewProps> = ({ scan }) => {
  const assessment: DomainAssessmentData = scan.domainAssessment || {};
  const { domainInfo, dnsRecords, ipInfo, webServer, sslDetails, emailSecurity } = assessment;

  // Helper for rendering values or "Not Available"
  const val = (v?: string | number | null | (string | number)[]) => {
    if (v === undefined || v === null || v === '') return 'Not Available';
    if (Array.isArray(v)) {
      return v.length > 0 ? v.join(', ') : 'Not Available';
    }
    return String(v);
  };

  const renderBadge = (value?: string) => {
    if (!value || value === 'Not Available') {
      return <span className="text-xs text-[#64748b] bg-[#0f172a] px-2 py-0.5 rounded font-mono">Not Available</span>;
    }
    return <span className="text-xs font-semibold text-[#38bdf8] bg-[#38bdf8]/10 border border-[#38bdf8]/30 px-2.5 py-0.5 rounded font-mono">{value}</span>;
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-6 space-y-2">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-[#3b82f6]/10 border border-[#3b82f6]/30 rounded-xl text-[#3b82f6]">
              <Globe className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-[#f8fafc]">Domain Reconnaissance & Assessment Report</h2>
              <div className="text-xs text-[#94a3b8] flex items-center space-x-2 mt-0.5">
                <span>Target: <code className="text-[#3b82f6] font-mono">{scan.target}</code></span>
                <span>•</span>
                <span>Type: <strong className="text-white uppercase">{scan.scanType}</strong></span>
                <span>•</span>
                <span>Risk Score: <strong className={scan.riskScore > 50 ? "text-[#ef4444]" : "text-[#10b981]"}>{scan.riskScore}/100</strong></span>
              </div>
            </div>
          </div>
          
          <div className="text-xs text-right text-[#94a3b8] font-mono">
            <div>Scan ID: {scan.id}</div>
            <div>Completed: {new Date(scan.startTime).toLocaleString()}</div>
          </div>
        </div>
      </div>

      {/* Grid of Sections */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* 1. DOMAIN INFORMATION */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-[#f8fafc] flex items-center space-x-2 border-b border-[#334155] pb-2 uppercase tracking-wide">
            <Globe className="w-4 h-4 text-[#3b82f6]" />
            <span>1. Domain Information</span>
          </h3>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Domain Name</div>
              <div className="font-mono text-[#f8fafc] font-semibold">{val(domainInfo?.domainName || scan.target)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Registered Domain</div>
              <div className="font-mono text-[#f8fafc]">{val(domainInfo?.registeredDomain || scan.target)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Registrar</div>
              <div className="text-[#cbd5e1]">{val(domainInfo?.registrar)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Domain Status</div>
              <div className="text-[#cbd5e1]">{val(domainInfo?.domainStatus)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Registration Date</div>
              <div className="font-mono text-[#cbd5e1]">{val(domainInfo?.registrationDate)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Expiration Date</div>
              <div className="font-mono text-[#cbd5e1]">{val(domainInfo?.expirationDate)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Last Updated Date</div>
              <div className="font-mono text-[#cbd5e1]">{val(domainInfo?.lastUpdatedDate)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">DNSSEC Status</div>
              <div className="text-[#cbd5e1]">{val(domainInfo?.dnssecStatus)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Name Servers</div>
              <div className="font-mono text-[#38bdf8]">{val(domainInfo?.nameServers)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Registrant Country</div>
              <div className="text-[#cbd5e1]">{val(domainInfo?.registrantCountry)}</div>
            </div>
          </div>
        </div>

        {/* 2. DNS ENUMERATION */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-[#f8fafc] flex items-center space-x-2 border-b border-[#334155] pb-2 uppercase tracking-wide">
            <Search className="w-4 h-4 text-[#3b82f6]" />
            <span>2. DNS Record Enumeration</span>
          </h3>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">A Record</div>
              <div className="font-mono text-[#10b981]">{val(dnsRecords?.aRecords)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">AAAA Record</div>
              <div className="font-mono text-[#cbd5e1]">{val(dnsRecords?.aaaaRecords)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">MX Records</div>
              <div className="font-mono text-[#cbd5e1]">{val(dnsRecords?.mxRecords)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">NS Records</div>
              <div className="font-mono text-[#cbd5e1]">{val(dnsRecords?.nsRecords)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">CNAME Records</div>
              <div className="font-mono text-[#cbd5e1]">{val(dnsRecords?.cnameRecords)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">TXT Records</div>
              <div className="font-mono text-[#cbd5e1]">{val(dnsRecords?.txtRecords)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">SOA Record</div>
              <div className="font-mono text-[#cbd5e1]">{val(dnsRecords?.soaRecord)}</div>
            </div>
          </div>
        </div>

        {/* 3. IP INFORMATION & HOSTING */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-[#f8fafc] flex items-center space-x-2 border-b border-[#334155] pb-2 uppercase tracking-wide">
            <Server className="w-4 h-4 text-[#3b82f6]" />
            <span>3. IP & Hosting Infrastructure</span>
          </h3>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Public IP Address</div>
              <div className="font-mono text-[#3b82f6] font-bold">{val(ipInfo?.publicIp || scan.target)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Reverse DNS</div>
              <div className="font-mono text-[#cbd5e1]">{val(ipInfo?.reverseDns)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">ASN Number</div>
              <div className="font-mono text-[#cbd5e1]">{val(ipInfo?.asnNumber)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">CDN Detection</div>
              <div className="text-[#cbd5e1]">{val(ipInfo?.cdnDetected)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">ISP / Hosting Provider</div>
              <div className="text-[#cbd5e1]">{val(ipInfo?.hostingProvider)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Organization</div>
              <div className="text-[#cbd5e1]">{val(ipInfo?.organization)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Country</div>
              <div className="text-[#cbd5e1]">{val(ipInfo?.country)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">City</div>
              <div className="text-[#cbd5e1]">{val(ipInfo?.city)}</div>
            </div>
          </div>
        </div>

        {/* 4. WEB SERVER & TECH STACK */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-[#f8fafc] flex items-center space-x-2 border-b border-[#334155] pb-2 uppercase tracking-wide">
            <Cpu className="w-4 h-4 text-[#3b82f6]" />
            <span>4. Web Server & Technology Stack</span>
          </h3>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Web Server</div>
              <div className="text-[#f8fafc] font-medium">{val(webServer?.webServer)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">CMS Detection</div>
              <div className="text-[#cbd5e1]">{val(webServer?.cmsDetected)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Framework</div>
              <div className="text-[#cbd5e1]">{val(webServer?.framework)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Programming Language</div>
              <div className="text-[#cbd5e1]">{val(webServer?.programmingLanguage)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Detected Technology Stack</div>
              <div className="font-mono text-[#38bdf8]">{val(webServer?.techStack)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">robots.txt</div>
              <div className="font-mono text-[#cbd5e1]">{val(webServer?.robotsTxt)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">sitemap.xml</div>
              <div className="font-mono text-[#cbd5e1]">{val(webServer?.sitemapXml)}</div>
            </div>
          </div>
        </div>

        {/* 5. SSL / TLS ASSESSMENT */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-[#f8fafc] flex items-center space-x-2 border-b border-[#334155] pb-2 uppercase tracking-wide">
            <Lock className="w-4 h-4 text-[#3b82f6]" />
            <span>5. SSL/TLS Cryptographic Assessment</span>
          </h3>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Certificate Issuer</div>
              <div className="text-[#f8fafc] font-medium">{val(sslDetails?.issuer)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Subject</div>
              <div className="font-mono text-[#cbd5e1]">{val(sslDetails?.subject)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Expiry Date</div>
              <div className="font-mono text-[#cbd5e1]">{val(sslDetails?.expiryDate)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Subject Alternative Names (SAN)</div>
              <div className="font-mono text-[#38bdf8]">{val(sslDetails?.san)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Supported TLS Versions</div>
              <div className="font-mono text-[#10b981]">{val(sslDetails?.tlsVersions)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Weak Ciphers</div>
              <div className="text-[#cbd5e1]">{val(sslDetails?.weakCiphers)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">HSTS Status</div>
              <div className="text-[#cbd5e1]">{val(sslDetails?.hstsStatus)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Heartbleed Vulnerability</div>
              <div className="font-semibold text-[#10b981]">{val(sslDetails?.heartbleedStatus)}</div>
            </div>
          </div>
        </div>

        {/* 6. EMAIL SECURITY */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-[#f8fafc] flex items-center space-x-2 border-b border-[#334155] pb-2 uppercase tracking-wide">
            <Mail className="w-4 h-4 text-[#3b82f6]" />
            <span>6. Email Security (SPF / DKIM / DMARC)</span>
          </h3>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">SPF Record</div>
              <div className="font-mono text-[#cbd5e1]">{val(emailSecurity?.spfRecord || dnsRecords?.spfRecord)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 col-span-2 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">DMARC Record</div>
              <div className="font-mono text-[#cbd5e1]">{val(emailSecurity?.dmarcRecord || dnsRecords?.dmarcRecord)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">DKIM Detection</div>
              <div className="text-[#cbd5e1]">{val(emailSecurity?.dkimStatus || dnsRecords?.dkimStatus)}</div>
            </div>

            <div className="bg-[#0f172a] p-2.5 rounded border border-[#334155]/60 space-y-0.5">
              <div className="text-[10px] text-[#64748b] uppercase font-bold">Open Relay Test</div>
              <div className="text-[#cbd5e1]">{val(emailSecurity?.openRelayStatus)}</div>
            </div>
          </div>
        </div>

      </div>

      {/* Raw Scanner Output & Telemetry Capture */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-bold text-[#f8fafc] flex items-center space-x-2 border-b border-[#334155] pb-2 uppercase tracking-wide">
          <FileText className="w-4 h-4 text-[#3b82f6]" />
          <span>7. Verified Scan Engine Raw Evidence Capture</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-1">
            <div className="text-[10px] uppercase font-bold text-[#64748b]">DNS / WHOIS Query Raw Output:</div>
            <pre className="bg-[#020617] border border-[#1e293b] rounded p-3 font-mono text-[11px] text-[#94a3b8] overflow-x-auto max-h-40 whitespace-pre-wrap">
              {scan.rawOutput?.whois || scan.rawOutput?.dns || 'Not Available'}
            </pre>
          </div>

          <div className="space-y-1">
            <div className="text-[10px] uppercase font-bold text-[#64748b]">Nmap / Port Scan Raw Output:</div>
            <pre className="bg-[#020617] border border-[#1e293b] rounded p-3 font-mono text-[11px] text-[#94a3b8] overflow-x-auto max-h-40 whitespace-pre-wrap">
              {scan.rawOutput?.nmap || 'Not Available'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
