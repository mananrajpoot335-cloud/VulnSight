import React from 'react';
import { 
  ShieldAlert, ShieldCheck, Activity, Server, AlertTriangle, 
  CheckCircle2, AlertOctagon, Info, FileText, Search, Play, Plus, Clock, Trash2
} from 'lucide-react';
import { 
  PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, AreaChart, Area 
} from 'recharts';
import { Asset, Vulnerability, ScanResult, DashboardStats } from '../types';

interface DashboardProps {
  stats: DashboardStats;
  assets: Asset[];
  vulnerabilities: Vulnerability[];
  scans: ScanResult[];
  onNavigateTab: (tab: string) => void;
  onSelectVulnerability: (vuln: Vulnerability) => void;
  onSelectScan: (scan: ScanResult) => void;
  onLaunchScanClick: () => void;
  onDeleteScan?: (scanId: string) => void;
  onDeleteVulnerability?: (vulnId: string) => void;
  onClearAllScans?: () => void;
}

export const DashboardOverview: React.FC<DashboardProps> = ({
  stats,
  assets,
  vulnerabilities,
  scans,
  onNavigateTab,
  onSelectVulnerability,
  onSelectScan,
  onLaunchScanClick,
  onDeleteScan,
  onDeleteVulnerability,
  onClearAllScans,
}) => {
  // Severity Chart Data
  const severityData = [
    { name: 'Critical', value: stats.criticalVulns, color: '#dc2626' },
    { name: 'High', value: stats.highVulns, color: '#ea580c' },
    { name: 'Medium', value: stats.mediumVulns, color: '#d97706' },
    { name: 'Low', value: stats.lowVulns, color: '#2563eb' },
    { name: 'Info', value: stats.infoVulns, color: '#64748b' },
  ];

  // Asset Risk Breakdown Chart
  const assetRiskData = assets.map(asset => ({
    name: asset.hostname.split('.')[0],
    Risk: asset.riskScore,
    Critical: asset.vulnerabilitiesCount.critical,
    High: asset.vulnerabilitiesCount.high,
  }));

  // Historical Risk Trend
  const trendData = [
    { date: 'Jul 17', RiskScore: 92, OpenVulns: 28 },
    { date: 'Jul 18', RiskScore: 89, OpenVulns: 25 },
    { date: 'Jul 19', RiskScore: 84, OpenVulns: 22 },
    { date: 'Jul 20', RiskScore: 86, OpenVulns: 23 },
    { date: 'Jul 21', RiskScore: 81, OpenVulns: 20 },
    { date: 'Jul 22', RiskScore: stats.overallRiskScore, OpenVulns: stats.openVulns },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Launcher */}
      <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-5 text-white flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-[#3b82f6]/10 text-[#3b82f6] border border-[#3b82f6]/30">
              Enterprise Network Security Status
            </span>
            <span className="text-xs text-[#94a3b8]">Scanning Engine Operational</span>
          </div>
          <h2 className="text-xl font-bold tracking-tight text-[#f8fafc]">Vulnerability Posture Dashboard</h2>
          <p className="text-xs text-[#94a3b8]">
            Real-time assessment across {stats.totalAssets} assets and {stats.totalScans} security scans.
          </p>
        </div>
        <div className="flex items-center space-x-3 w-full md:w-auto">
          {(scans.length > 0 || vulnerabilities.length > 0) && onClearAllScans && (
            <button
              onClick={onClearAllScans}
              className="flex-1 md:flex-none flex items-center justify-center space-x-2 bg-[#0f172a] hover:bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/40 font-semibold px-3 py-2 rounded-md shadow transition-all text-xs"
              title="Delete all scans and clear dashboard"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear All Scans</span>
            </button>
          )}

          <button
            id="btn-quick-scan"
            onClick={onLaunchScanClick}
            className="flex-1 md:flex-none flex items-center justify-center space-x-2 bg-[#3b82f6] hover:bg-blue-600 text-white font-semibold px-4 py-2 rounded-md shadow-md transition-all text-xs"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Launch New Scan</span>
          </button>
        </div>
      </div>

      {/* Primary KPI Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        {/* Total Assets */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-4 flex flex-col justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8]">Total Assets</div>
          <div className="text-2xl font-bold text-[#f8fafc] mt-1">{stats.totalAssets}</div>
          <div className="text-[11px] text-[#10b981] mt-2 flex items-center space-x-1">
            <Activity className="w-3 h-3" />
            <span>{stats.activeHosts} Online</span>
          </div>
        </div>

        {/* Risk Score */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-4 flex flex-col justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8]">Risk Score</div>
          <div className="text-2xl font-bold text-[#f8fafc] mt-1">
            {stats.overallRiskScore}<span className="text-xs text-[#94a3b8] font-normal"> / 100</span>
          </div>
          <div className="text-[11px] text-[#eab308] mt-2">Medium-High Risk</div>
        </div>

        {/* Critical Findings */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-4 flex flex-col justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8]">Critical Findings</div>
          <div className="text-2xl font-bold text-[#ef4444] mt-1">{stats.criticalVulns}</div>
          <div className="text-[11px] text-[#ef4444] mt-2">Action required</div>
        </div>

        {/* High Findings */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-4 flex flex-col justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8]">High Severity</div>
          <div className="text-2xl font-bold text-[#f97316] mt-1">{stats.highVulns}</div>
          <div className="text-[11px] text-[#f97316] mt-2">P2 Priority</div>
        </div>

        {/* Remediation Rate */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-4 flex flex-col justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8]">Remediation Rate</div>
          <div className="text-2xl font-bold text-[#10b981] mt-1">92%</div>
          <div className="text-[11px] text-[#94a3b8] mt-2">vs 88% last month</div>
        </div>

        {/* Security Score */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-4 flex flex-col justify-between">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8]">Security Score</div>
          <div className="text-2xl font-bold text-[#10b981] mt-1">{stats.securityScore}%</div>
          <div className="text-[11px] text-[#10b981] mt-2">Grade: A-</div>
        </div>
      </div>

      {/* Analytics Charts & AI Insight Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown Pie */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              Severity Distribution
            </h3>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', borderRadius: '6px', color: '#f8fafc', fontSize: '12px' }}
                />
                <Legend verticalAlign="bottom" height={32} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Asset Risk Comparison Bar Chart */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              Asset Risk Index
            </h3>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={assetRiskData}>
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', borderRadius: '6px', color: '#f8fafc', fontSize: '12px' }}
                />
                <Bar dataKey="Risk" fill="#3b82f6" radius={[3, 3, 0, 0]} name="Risk Index" />
                <Bar dataKey="Critical" fill="#ef4444" radius={[3, 3, 0, 0]} name="Critical Count" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* AI Remediation Insight Box (from Sophisticated Dark Theme) */}
        <div className="bg-gradient-to-br from-[#3b82f6]/10 to-[#9333ea]/10 border border-[#3b82f6]/30 rounded-lg p-5 flex flex-col justify-between relative">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs font-semibold uppercase tracking-wider text-[#a855f7] flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-[#a855f7] animate-pulse" />
                <span>AI Remediation Insight</span>
              </div>
              <ShieldAlert className="w-4 h-4 text-[#a855f7]" />
            </div>

            <div className="text-xs leading-relaxed text-[#e2e8f0] space-y-2">
              <p>
                <strong className="text-white">CVE-2024-21887</strong> detected on <strong className="text-white">WEB-PROD-01</strong>. AI identifies high exploitation risk.
              </p>
              <blockquote className="p-2.5 rounded bg-[#0f172a]/80 border border-[#3b82f6]/20 text-[#94a3b8] italic">
                &quot;Patch to Ivy-9.1.3 immediately or restrict port 443 access to authorized IPs via iptables.&quot;
              </blockquote>
            </div>
          </div>

          <button
            onClick={() => onNavigateTab('vulnerabilities')}
            className="mt-4 bg-[#3b82f6] hover:bg-blue-600 text-white font-semibold py-2 px-3 rounded text-xs transition-all w-fit shadow"
          >
            View AI Guide
          </button>
        </div>
      </div>

      {/* Recent Critical Vulnerabilities Table & Recent Scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Priority Unresolved Vulnerabilities */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#334155] pb-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              Priority Unresolved Vulnerabilities
            </h3>
            <button
              onClick={() => onNavigateTab('vulnerabilities')}
              className="text-xs text-[#3b82f6] hover:underline font-medium"
            >
              View All ({vulnerabilities.length}) →
            </button>
          </div>

          <div className="space-y-2.5">
            {vulnerabilities.length === 0 ? (
              <div className="p-6 text-center text-xs text-[#94a3b8] bg-[#0f172a] rounded-md border border-[#334155]">
                No active vulnerabilities found.
              </div>
            ) : (
              vulnerabilities.slice(0, 4).map((vuln) => (
                <div
                  key={vuln.id}
                  onClick={() => onSelectVulnerability(vuln)}
                  className="p-3 bg-[#0f172a] hover:bg-[#020617] border border-[#334155] rounded-md cursor-pointer transition-all flex items-start justify-between gap-3 group"
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${
                        vuln.severity === 'Critical' ? 'bg-[#ef4444]/20 text-[#ef4444]' :
                        vuln.severity === 'High' ? 'bg-[#f97316]/20 text-[#f97316]' :
                        'bg-[#eab308]/20 text-[#eab308]'
                      }`}>
                        {vuln.severity} ({vuln.cvssScore})
                      </span>
                      {vuln.cveId && (
                        <span className="text-[11px] font-mono text-[#94a3b8] bg-[#1e293b] px-1.5 py-0.5 rounded border border-[#334155]">
                          {vuln.cveId}
                        </span>
                      )}
                    </div>
                    <h4 className="text-xs font-semibold text-[#f8fafc] group-hover:text-[#3b82f6] transition-colors line-clamp-1">
                      {vuln.title}
                    </h4>
                    <div className="text-[11px] text-[#94a3b8]">
                      Target Host: <code className="text-[#3b82f6]">{vuln.affectedHost}</code>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0">
                    <div className="text-right">
                      <span className="text-[11px] text-[#94a3b8] block">{new Date(vuln.detectedAt).toLocaleDateString()}</span>
                      <span className="inline-block mt-1 text-[10px] px-2 py-0.5 rounded bg-[#1e293b] text-[#10b981] font-semibold">
                        {vuln.status}
                      </span>
                    </div>

                    {onDeleteVulnerability && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onDeleteVulnerability(vuln.id);
                        }}
                        title="Delete vulnerability finding"
                        className="p-1.5 text-[#94a3b8] hover:text-[#ef4444] hover:bg-[#1e293b] rounded transition-all ml-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Assessment Scans */}
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-[#334155] pb-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-[#94a3b8]">
              Recent Assessment Scans
            </h3>
            <button
              onClick={() => onNavigateTab('scans')}
              className="text-xs text-[#3b82f6] hover:underline font-medium"
            >
              Scan History →
            </button>
          </div>

          <div className="space-y-2.5">
            {scans.length === 0 ? (
              <div className="p-6 text-center text-xs text-[#94a3b8] bg-[#0f172a] rounded-md border border-[#334155]">
                No assessment scans recorded. Launch a new scan above.
              </div>
            ) : (
              scans.slice(0, 4).map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => onSelectScan(scan)}
                  className="p-3 bg-[#0f172a] hover:bg-[#020617] border border-[#334155] rounded-md cursor-pointer transition-all flex items-center justify-between gap-3 group"
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-[#f8fafc] group-hover:text-[#3b82f6] transition-colors truncate">
                        {scan.name}
                      </span>
                      <span className="px-1.5 py-0.5 text-[10px] bg-[#1e293b] text-[#94a3b8] rounded uppercase shrink-0">
                        {scan.scanType}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#94a3b8]">
                      Target: <code className="text-[#3b82f6]">{scan.target}</code>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0">
                    <div className="text-right">
                      <div className="flex items-center space-x-1.5 justify-end text-xs font-mono font-bold text-[#f8fafc]">
                        <span>Risk: {scan.riskScore}</span>
                        <span className="w-2 h-2 rounded-full bg-[#10b981]" />
                      </div>
                      <span className="text-[10px] text-[#94a3b8] block mt-0.5">
                        {new Date(scan.startTime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>

                    {onDeleteScan && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm(`Delete scan for ${scan.target}? All associated vulnerability reports for this IP will be deleted.`)) {
                            onDeleteScan(scan.id);
                          }
                        }}
                        title="Delete scan and all report findings"
                        className="p-1.5 text-[#94a3b8] hover:text-[#ef4444] hover:bg-[#1e293b] rounded transition-all ml-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
