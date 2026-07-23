import React, { useState } from 'react';
import { 
  FileText, Download, CheckCircle, AlertTriangle, Shield, Printer, ExternalLink, Sparkles
} from 'lucide-react';
import { ScanResult, Vulnerability, DashboardStats } from '../types';

interface ReportGeneratorProps {
  scans: ScanResult[];
  vulnerabilities: Vulnerability[];
  stats: DashboardStats;
}

export const ReportGenerator: React.FC<ReportGeneratorProps> = ({ scans, vulnerabilities, stats }) => {
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || '');
  const [reportFormat, setReportFormat] = useState<'HTML' | 'CSV' | 'PDF'>('HTML');
  const [printNotice, setPrintNotice] = useState<string | null>(null);

  const selectedScan = scans.find(s => s.id === selectedScanId) || scans[0];

  const handleDownloadCSV = () => {
    const headers = ['ID', 'Title', 'Severity', 'CVSS', 'CVE', 'Affected Host', 'Port', 'Status', 'Recommendation'];
    const rows = vulnerabilities.map(v => [
      v.id,
      `"${v.title.replace(/"/g, '""')}"`,
      v.severity,
      v.cvssScore,
      v.cveId || 'N/A',
      v.affectedHost,
      v.affectedPort || 'N/A',
      v.status,
      `"${v.recommendation.replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `VulnSight_Executive_Report_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handlePrintHTML = () => {
    // Generate clean printable HTML document
    const reportHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>VulnSight_Executive_Report_${new Date().toISOString().slice(0, 10)}</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 40px; color: #0f172a; max-width: 900px; margin: 0 auto; }
            .header { display: flex; justify-content: space-between; border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; }
            .title { font-size: 24px; font-weight: 800; color: #1e293b; }
            .meta { font-size: 12px; font-family: monospace; color: #64748b; text-align: right; }
            .section-title { font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; margin-top: 24px; margin-bottom: 12px; color: #334155; }
            .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; text-align: center; margin-bottom: 24px; }
            .stat-box { border: 1px solid #e2e8f0; padding: 12px; rounded: 8px; border-radius: 6px; background: #f8fafc; }
            .stat-val { font-size: 20px; font-weight: 800; }
            .stat-lbl { font-size: 10px; font-weight: 700; text-transform: uppercase; margin-top: 4px; }
            .vuln-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; background: #ffffff; page-break-inside: avoid; }
            .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; margin-right: 8px; }
            .badge-critical { background: #fee2e2; color: #991b1b; }
            .badge-high { background: #ffedd5; color: #9a3412; }
            .badge-medium { background: #fef9c3; color: #854d0e; }
            .remediation { background: #f1f5f9; border-left: 4px solid #10b981; padding: 10px 14px; font-family: monospace; font-size: 11px; margin-top: 8px; color: #0f172a; border-radius: 0 4px 4px 0; }
            @media print {
              body { padding: 0; }
              .no-print { display: none; }
            }
          </style>
        </head>
        <body>
          <div className="no-print" style="margin-bottom: 20px; background: #e0f2fe; padding: 12px; border-radius: 6px; font-size: 13px; color: #0369a1;">
            💡 <strong>Print / PDF Ready:</strong> Use your browser's Print dialog below (or press <strong>Ctrl + P</strong> / <strong>Cmd + P</strong>) to save as PDF or send to printer.
          </div>
          <div class="header">
            <div>
              <div class="title">🛡️ VulnSight Executive Security Report</div>
              <div style="font-size: 12px; color: #64748b; margin-top: 4px;">Automated Vulnerability & Infrastructure Risk Assessment</div>
            </div>
            <div class="meta">
              <div>Report ID: VNS-RPT-${Math.floor(100000 + Math.random() * 900000)}</div>
              <div>Generated: ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}</div>
              <div>Target: ${selectedScan?.target || 'All Hosts'}</div>
            </div>
          </div>

          <div class="section-title">1. Executive Risk Summary</div>
          <p style="font-size: 13px; line-height: 1.6; color: #334155;">
            During the security assessment targeting <code>${selectedScan?.target || 'Network Infrastructure'}</code>, VulnSight identified a total of <strong>${vulnerabilities.length} security findings</strong>. Overall calculated Host Risk Score is <strong>${stats.overallRiskScore} / 100</strong>.
          </p>

          <div class="section-title">2. Vulnerability Severity Breakdown</div>
          <div class="stats-grid">
            <div class="stat-box">
              <div class="stat-val" style="color: #dc2626;">${stats.criticalVulns}</div>
              <div class="stat-lbl" style="color: #991b1b;">Critical</div>
            </div>
            <div class="stat-box">
              <div class="stat-val" style="color: #ea580c;">${stats.highVulns}</div>
              <div class="stat-lbl" style="color: #9a3412;">High</div>
            </div>
            <div class="stat-box">
              <div class="stat-val" style="color: #ca8a04;">${stats.mediumVulns}</div>
              <div class="stat-lbl" style="color: #854d0e;">Medium</div>
            </div>
            <div class="stat-box">
              <div class="stat-val" style="color: #2563eb;">${stats.lowVulns}</div>
              <div class="stat-lbl" style="color: #1e40af;">Low</div>
            </div>
            <div class="stat-box">
              <div class="stat-val" style="color: #64748b;">${stats.infoVulns}</div>
              <div class="stat-lbl" style="color: #475569;">Info</div>
            </div>
          </div>

          <div class="section-title">3. Detailed Security Findings & Remediation Roadmap</div>
          ${vulnerabilities.map((v, i) => `
            <div class="vuln-card">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div>
                  <span class="badge badge-${v.severity.toLowerCase()}">${v.severity} (CVSS ${v.cvssScore})</span>
                  ${v.cveId ? `<span style="font-family: monospace; font-size: 11px; background: #e2e8f0; padding: 2px 6px; border-radius: 4px;">${v.cveId}</span>` : ''}
                </div>
                <div style="font-family: monospace; font-size: 11px; color: #64748b;">Host: ${v.affectedHost}${v.affectedPort ? ':' + v.affectedPort : ''}</div>
              </div>
              <div style="font-weight: 700; font-size: 14px; color: #0f172a; margin-bottom: 6px;">${i + 1}. ${v.title}</div>
              <div style="font-size: 12px; color: #475569; line-height: 1.5; margin-bottom: 10px;">${v.description}</div>
              <div class="remediation">
                <strong>🔧 Remediation Command / Fix:</strong><br/>
                ${v.remediation.manualFix}
              </div>
            </div>
          `).join('')}
        </body>
      </html>
    `;

    try {
      const printWindow = window.open('', '_blank');
      if (printWindow) {
        printWindow.document.open();
        printWindow.document.write(reportHtml);
        printWindow.document.close();
        printWindow.focus();
        setTimeout(() => {
          printWindow.print();
        }, 500);
      } else {
        // Fallback if popup blocked
        window.print();
      }
    } catch (err) {
      console.warn('Iframe print intercepted:', err);
      setPrintNotice('Print dialog was blocked by iframe preview sandbox. Click "Export HTML" or open the app in a new browser tab to print directly to PDF.');
      setTimeout(() => setPrintNotice(null), 7000);
    }
  };

  const handleDownloadHTML = () => {
    const reportHtml = `<!DOCTYPE html><html><head><title>VulnSight_Executive_Report</title><style>body{font-family:sans-serif;padding:30px;color:#0f172a;max-width:900px;margin:0 auto;}.card{border:1px solid #cbd5e1;padding:16px;margin-bottom:12px;border-radius:6px;}.rem{background:#f1f5f9;padding:10px;font-family:monospace;margin-top:8px;}</style></head><body><h1>🛡️ VulnSight Executive Security Report</h1><p>Target: ${selectedScan?.target || 'All Hosts'} | Risk Score: ${stats.overallRiskScore}/100</p><h2>Findings</h2>${vulnerabilities.map((v, i) => `<div class="card"><h3>${i+1}. [${v.severity}] ${v.title}</h3><p>${v.description}</p><div class="rem"><b>Fix:</b> ${v.remediation.manualFix}</div></div>`).join('')}</body></html>`;
    const blob = new Blob([reportHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VulnSight_Security_Report_${new Date().toISOString().slice(0,10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {printNotice && (
        <div className="bg-[#3b82f6]/10 border border-[#3b82f6]/30 p-3 rounded-md text-xs text-[#3b82f6] font-medium flex items-center justify-between">
          <span>{printNotice}</span>
          <button onClick={() => setPrintNotice(null)} className="text-[#94a3b8] hover:text-white ml-2">✕</button>
        </div>
      )}

      {/* Controls Bar */}
      <div className="bg-[#1e293b] border border-[#334155] p-5 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-4 print:hidden">
        <div>
          <h2 className="text-lg font-bold text-[#f8fafc] flex items-center space-x-2 uppercase tracking-wide">
            <FileText className="w-5 h-5 text-[#3b82f6]" />
            <span>Executive Security Report Generator</span>
          </h2>
          <p className="text-xs text-[#94a3b8] mt-0.5">
            Export comprehensive vulnerability assessment, CVSS metrics, and step-by-step remediation plan.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="bg-[#0f172a] border border-[#334155] text-xs text-[#f8fafc] rounded-md px-3 py-1.5 font-medium"
          >
            {scans.map(s => (
              <option key={s.id} value={s.id}>Scan: {s.name} ({s.target})</option>
            ))}
          </select>

          <button
            onClick={handleDownloadCSV}
            className="bg-[#0f172a] hover:bg-[#334155] text-[#f8fafc] border border-[#334155] font-semibold px-3.5 py-1.5 rounded-md text-xs flex items-center space-x-1.5 transition-all"
            title="Download structured raw findings in CSV format"
          >
            <Download className="w-3.5 h-3.5 text-[#94a3b8]" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={handleDownloadHTML}
            className="bg-[#0f172a] hover:bg-[#334155] text-[#f8fafc] border border-[#334155] font-semibold px-3.5 py-1.5 rounded-md text-xs flex items-center space-x-1.5 transition-all"
            title="Download standalone HTML report file"
          >
            <FileText className="w-3.5 h-3.5 text-[#3b82f6]" />
            <span>Export HTML</span>
          </button>

          <button
            onClick={handlePrintHTML}
            className="bg-[#3b82f6] hover:bg-blue-600 text-white font-semibold px-4 py-1.5 rounded-md text-xs flex items-center space-x-1.5 shadow transition-all"
            title="Open printable view and trigger browser print dialog"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print / PDF Report</span>
          </button>
        </div>
      </div>

      {/* Printable Report Document Body */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-8 space-y-8 print:bg-white print:text-black print:border-none print:shadow-none">
        {/* Document Header */}
        <div className="border-b border-[#334155] print:border-slate-300 pb-6 flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <Shield className="w-7 h-7 text-[#3b82f6]" />
              <span className="text-2xl font-black tracking-tight text-[#f8fafc] print:text-black">VulnSight</span>
            </div>
            <p className="text-xs text-[#94a3b8] print:text-slate-600">Enterprise Cybersecurity Vulnerability Assessment Report</p>
          </div>
          <div className="text-right text-xs text-[#94a3b8] print:text-slate-600 space-y-0.5 font-mono">
            <div>Report ID: VNS-RPT-2026-0723</div>
            <div>Generated: {new Date().toLocaleDateString()} {new Date().toLocaleTimeString()}</div>
            <div>Classification: RESTRICTED / INTERNAL USE</div>
          </div>
        </div>

        {/* Executive Summary Section */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-[#f8fafc] print:text-black uppercase tracking-wider border-b border-[#334155] print:border-slate-300 pb-1">
            1. Executive Summary
          </h3>
          <p className="text-xs text-[#94a3b8] print:text-slate-800 leading-relaxed">
            During the automated security assessment targeting <code className="font-mono text-[#3b82f6]">{selectedScan?.target}</code>, VulnSight evaluated network host accessibility, service version disclosures, web application configurations, and SSL/TLS cryptographic parameters. A total of <strong className="text-[#f8fafc] print:text-black">{vulnerabilities.length} security findings</strong> were identified across the target infrastructure, resulting in an overall host Risk Score of <strong className="text-[#ef4444]">{stats.overallRiskScore} / 100</strong>.
          </p>
        </div>

        {/* Vulnerability Severity Matrix */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-[#f8fafc] print:text-black uppercase tracking-wider border-b border-[#334155] print:border-slate-300 pb-1">
            2. Severity Metrics Breakdown
          </h3>
          <div className="grid grid-cols-5 gap-3 text-center">
            <div className="bg-[#ef4444]/10 border border-[#ef4444]/30 p-3 rounded-lg">
              <div className="text-xl font-bold text-[#ef4444]">{stats.criticalVulns}</div>
              <div className="text-[10px] text-[#ef4444] font-semibold uppercase">Critical</div>
            </div>
            <div className="bg-[#f97316]/10 border border-[#f97316]/30 p-3 rounded-lg">
              <div className="text-xl font-bold text-[#f97316]">{stats.highVulns}</div>
              <div className="text-[10px] text-[#f97316] font-semibold uppercase">High</div>
            </div>
            <div className="bg-[#eab308]/10 border border-[#eab308]/30 p-3 rounded-lg">
              <div className="text-xl font-bold text-[#eab308]">{stats.mediumVulns}</div>
              <div className="text-[10px] text-[#eab308] font-semibold uppercase">Medium</div>
            </div>
            <div className="bg-[#3b82f6]/10 border border-[#3b82f6]/30 p-3 rounded-lg">
              <div className="text-xl font-bold text-[#3b82f6]">{stats.lowVulns}</div>
              <div className="text-[10px] text-[#3b82f6] font-semibold uppercase">Low</div>
            </div>
            <div className="bg-[#0f172a] border border-[#334155] p-3 rounded-lg">
              <div className="text-xl font-bold text-[#94a3b8]">{stats.infoVulns}</div>
              <div className="text-[10px] text-[#94a3b8] font-semibold uppercase">Info</div>
            </div>
          </div>
        </div>

        {/* Detailed Findings Table */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold text-[#f8fafc] print:text-black uppercase tracking-wider border-b border-[#334155] print:border-slate-300 pb-1">
            3. Detailed Vulnerability Findings & Fix Guidance
          </h3>
          <div className="space-y-4">
            {vulnerabilities.map((v, idx) => (
              <div key={v.id} className="p-4 bg-[#0f172a] border border-[#334155] rounded-lg space-y-2 print:border-slate-300 print:bg-slate-50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs text-[#94a3b8]">#{idx + 1}</span>
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${
                      v.severity === 'Critical' ? 'bg-[#ef4444]/20 text-[#ef4444]' :
                      v.severity === 'High' ? 'bg-[#f97316]/20 text-[#f97316]' :
                      'bg-[#eab308]/20 text-[#eab308]'
                    }`}>
                      {v.severity} (CVSS {v.cvssScore})
                    </span>
                    {v.cveId && <span className="font-mono text-xs text-[#94a3b8] bg-[#1e293b] px-1.5 py-0.5 rounded border border-[#334155]">{v.cveId}</span>}
                  </div>
                  <span className="text-xs font-mono text-[#94a3b8]">{v.affectedHost}:{v.affectedPort || 'N/A'}</span>
                </div>

                <h4 className="text-sm font-bold text-[#f8fafc] print:text-black">{v.title}</h4>
                <p className="text-xs text-[#94a3b8] print:text-slate-800 leading-relaxed">{v.description}</p>

                <div className="pt-2 border-t border-[#334155] print:border-slate-200 text-xs text-[#94a3b8] space-y-1">
                  <div className="font-semibold text-[#10b981] print:text-emerald-700">Remediation Step:</div>
                  <div className="font-mono bg-[#1e293b] p-2 rounded border border-[#334155] text-[11px] text-[#10b981] print:bg-white print:border-slate-300 print:text-slate-900">
                    {v.remediation.manualFix}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
