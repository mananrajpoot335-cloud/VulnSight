import React, { useState } from 'react';
import { 
  Shield, LayoutDashboard, Terminal, Server, FileText, Settings, Users, 
  Calendar, CheckSquare, Activity, LogOut, Sun, Moon, Search, AlertTriangle, ChevronRight, User as UserIcon, Trash2, Code2
} from 'lucide-react';
import { 
  Asset, Vulnerability, ScanResult, ScheduledScan, RemediationTask, ActivityLog, DashboardStats, User, VulnerabilityStatus
} from './types';
import { 
  INITIAL_ASSETS, INITIAL_VULNERABILITIES, INITIAL_SCANS, 
  INITIAL_SCHEDULED_SCANS, INITIAL_REMEDIATION_TASKS, INITIAL_ACTIVITY_LOGS 
} from './mockData';

import { DashboardOverview } from './components/DashboardOverview';
import { ScanConsole } from './components/ScanConsole';
import { AssetInventory } from './components/AssetInventory';
import { ReportGenerator } from './components/ReportGenerator';
import { VulnerabilityDetailModal } from './components/VulnerabilityDetailModal';
import { DeveloperDiagnostics } from './components/DeveloperDiagnostics';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);
  
  // App Data State - Defaulting to clean real-data posture (No hardcoded/demo vulnerabilities)
  const [assets, setAssets] = useState<Asset[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([]);
  const [remediationTasks, setRemediationTasks] = useState<RemediationTask[]>([]);
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>([]);

  // Modal State
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);

  // Authenticated User State
  const [currentUser] = useState<User>({
    id: 'usr-admin',
    name: 'Security Administrator',
    email: 'admin@vulnsight.local',
    role: 'Admin',
    lastLogin: new Date().toISOString()
  });

  // Calculate Dashboard Metrics dynamically from verified scan results
  const openCritical = vulnerabilities.filter(v => v.severity === 'Critical' && v.status !== 'Fixed').length;
  const openHigh = vulnerabilities.filter(v => v.severity === 'High' && v.status !== 'Fixed').length;
  const openMedium = vulnerabilities.filter(v => v.severity === 'Medium' && v.status !== 'Fixed').length;
  const calculatedRisk = Math.min(100, (openCritical * 30) + (openHigh * 15) + (openMedium * 5));
  const calculatedSecurity = Math.max(0, 100 - calculatedRisk);

  const stats: DashboardStats = {
    totalAssets: assets.length,
    totalScans: scans.length,
    activeHosts: assets.filter(a => a.status === 'Online').length,
    criticalVulns: openCritical,
    highVulns: openHigh,
    mediumVulns: openMedium,
    lowVulns: vulnerabilities.filter(v => v.severity === 'Low' && v.status !== 'Fixed').length,
    infoVulns: vulnerabilities.filter(v => v.severity === 'Informational' && v.status !== 'Fixed').length,
    fixedVulns: vulnerabilities.filter(v => v.status === 'Fixed').length,
    openVulns: vulnerabilities.filter(v => v.status !== 'Fixed').length,
    overallRiskScore: calculatedRisk,
    securityScore: calculatedSecurity
  };

  // Launch New Scan handler
  const handleRunScan = async (scanParams: any) => {
    const response = await fetch('/api/scans/launch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(scanParams)
    });
    const newScan: ScanResult = await response.json();
    setScans(prev => [newScan, ...prev]);

    if (newScan.vulnerabilities && newScan.vulnerabilities.length > 0) {
      setVulnerabilities(prev => [...newScan.vulnerabilities, ...prev]);
    }

    // Add activity log
    const newLog: ActivityLog = {
      id: 'act-' + Date.now(),
      timestamp: new Date().toISOString(),
      user: currentUser.email,
      action: 'Scan Launched',
      details: `Executed ${newScan.scanType} scan for target ${newScan.target}`,
      category: 'Scan'
    };
    setActivityLogs(prev => [newLog, ...prev]);

    return newScan;
  };

  // Delete Scan Handler (Deletes scan + all associated vulnerabilities, assets and report data)
  const handleDeleteScan = (scanId: string) => {
    const targetScan = scans.find(s => s.id === scanId);
    if (!targetScan) return;

    const targetIp = targetScan.target;
    const discoveredIps = targetScan.discoveredHosts?.map(h => h.ip) || [];

    // Remove scan from state
    setScans(prev => prev.filter(s => s.id !== scanId));

    // Remove all vulnerabilities associated with this scan ID or target IP
    setVulnerabilities(prev => prev.filter(v => {
      if (v.scanId === scanId) return false;
      if (v.affectedHost === targetIp) return false;
      if (discoveredIps.includes(v.affectedHost)) return false;
      return true;
    }));

    // Remove assets matching target IP or discovered hosts
    setAssets(prev => prev.filter(a => a.ip !== targetIp && !discoveredIps.includes(a.ip)));

    // Clear modal if active vuln belonged to deleted scan
    if (selectedVulnerability && (selectedVulnerability.scanId === scanId || selectedVulnerability.affectedHost === targetIp)) {
      setSelectedVulnerability(null);
    }

    // Add activity log
    const newLog: ActivityLog = {
      id: 'act-' + Date.now(),
      timestamp: new Date().toISOString(),
      user: currentUser.email,
      action: 'Scan Purged',
      details: `Deleted scan (${targetScan.name}), assets, and vulnerabilities for target ${targetIp}`,
      category: 'System'
    };
    setActivityLogs(prev => [newLog, ...prev]);
  };

  // Delete Individual Asset
  const handleDeleteAsset = (assetId: string) => {
    const targetAsset = assets.find(a => a.id === assetId);
    if (!targetAsset) return;

    setAssets(prev => prev.filter(a => a.id !== assetId));

    // Also remove vulnerabilities for this asset IP
    setVulnerabilities(prev => prev.filter(v => v.affectedHost !== targetAsset.ip));

    const newLog: ActivityLog = {
      id: 'act-' + Date.now(),
      timestamp: new Date().toISOString(),
      user: currentUser.email,
      action: 'Asset Deleted',
      details: `Removed asset ${targetAsset.hostname} (${targetAsset.ip}) from inventory`,
      category: 'System'
    };
    setActivityLogs(prev => [newLog, ...prev]);
  };

  // Clear All Assets
  const handleClearAllAssets = () => {
    if (window.confirm('Are you sure you want to delete all assets from inventory?')) {
      setAssets([]);
      const newLog: ActivityLog = {
        id: 'act-' + Date.now(),
        timestamp: new Date().toISOString(),
        user: currentUser.email,
        action: 'Assets Cleared',
        details: 'Purged all assets from inventory',
        category: 'System'
      };
      setActivityLogs(prev => [newLog, ...prev]);
    }
  };

  // Delete Individual Vulnerability Finding
  const handleDeleteVulnerability = (vulnId: string) => {
    const targetVuln = vulnerabilities.find(v => v.id === vulnId);
    if (!targetVuln) return;

    setVulnerabilities(prev => prev.filter(v => v.id !== vulnId));
    if (selectedVulnerability && selectedVulnerability.id === vulnId) {
      setSelectedVulnerability(null);
    }

    const newLog: ActivityLog = {
      id: 'act-' + Date.now(),
      timestamp: new Date().toISOString(),
      user: currentUser.email,
      action: 'Vulnerability Deleted',
      details: `Deleted finding '${targetVuln.title}' on ${targetVuln.affectedHost}`,
      category: 'Vulnerability'
    };
    setActivityLogs(prev => [newLog, ...prev]);
  };

  // Clear All Scans, Vulnerabilities, and Assets
  const handleClearAllScans = () => {
    if (window.confirm('Are you sure you want to delete all scan history, assets, and vulnerability findings? This will completely reset your dashboard.')) {
      setScans([]);
      setVulnerabilities([]);
      setAssets([]);
      setSelectedVulnerability(null);

      const newLog: ActivityLog = {
        id: 'act-' + Date.now(),
        timestamp: new Date().toISOString(),
        user: currentUser.email,
        action: 'Dashboard Reset',
        details: 'Purged all assessment scans, assets, and vulnerability reports',
        category: 'System'
      };
      setActivityLogs(prev => [newLog, ...prev]);
    }
  };

  // Status Change Handler for Vulnerabilities
  const handleVulnerabilityStatusChange = (vulnId: string, newStatus: VulnerabilityStatus) => {
    setVulnerabilities(prev => prev.map(v => v.id === vulnId ? { ...v, status: newStatus } : v));
    if (selectedVulnerability && selectedVulnerability.id === vulnId) {
      setSelectedVulnerability(prev => prev ? { ...prev, status: newStatus } : null);
    }
  };

  // Request AI Vulnerability Analysis
  const handleRequestAiAnalysis = async (vuln: Vulnerability) => {
    setIsAiLoading(true);
    try {
      const response = await fetch('/api/ai-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vulnerability: vuln })
      });
      const aiResult = await response.json();
      
      const updatedVuln = { ...vuln, aiAnalysis: aiResult };
      setSelectedVulnerability(updatedVuln);
      setVulnerabilities(prev => prev.map(v => v.id === vuln.id ? updatedVuln : v));
    } catch (err) {
      console.error(err);
    } finally {
      setIsAiLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-[#f8fafc] flex font-sans dark">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-[#020617] border-r border-[#1e293b] flex flex-col justify-between shrink-0 hidden md:flex">
        <div className="p-5 space-y-6">
          {/* Brand */}
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-[#3b82f6] flex items-center justify-center shadow-lg shadow-blue-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-extrabold text-xl tracking-tight text-[#3b82f6] leading-none">
                VULNSIGHT<span className="text-[#f8fafc]">.ai</span>
              </div>
              <span className="text-[10px] text-[#94a3b8] font-mono tracking-wider uppercase font-medium">Scanning Engine v2.4.0</span>
            </div>
          </div>

          {/* Navigation Items */}
          <nav className="space-y-1 text-xs font-medium">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-[#64748b] px-3 pb-1">
              Core Assessment
            </div>
            
            <button
              id="nav-dashboard"
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'dashboard' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <LayoutDashboard className="w-4 h-4" />
                <span>Dashboard Overview</span>
              </div>
            </button>

            <button
              id="nav-scans"
              onClick={() => setActiveTab('scans')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'scans' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Terminal className="w-4 h-4" />
                <span>Scan Console</span>
              </div>
            </button>

            <button
              id="nav-vulnerabilities"
              onClick={() => setActiveTab('vulnerabilities')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'vulnerabilities' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <AlertTriangle className="w-4 h-4" />
                <span>Vulnerabilities</span>
              </div>
              <span className="bg-[#ef4444]/20 text-[#ef4444] px-1.5 py-0.2 rounded font-bold text-[10px]">
                {stats.openVulns}
              </span>
            </button>

            <button
              id="nav-assets"
              onClick={() => setActiveTab('assets')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'assets' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Server className="w-4 h-4" />
                <span>Asset Inventory</span>
              </div>
            </button>

            <div className="text-[10px] font-semibold uppercase tracking-wider text-[#64748b] px-3 pt-4 pb-1">
              Enterprise & Reports
            </div>

            <button
              id="nav-reports"
              onClick={() => setActiveTab('reports')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'reports' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <FileText className="w-4 h-4" />
                <span>Executive Reports</span>
              </div>
            </button>

            <button
              id="nav-tasks"
              onClick={() => setActiveTab('tasks')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'tasks' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <CheckSquare className="w-4 h-4" />
                <span>Remediation Tasks</span>
              </div>
            </button>

            <button
              id="nav-logs"
              onClick={() => setActiveTab('logs')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'logs' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Activity className="w-4 h-4" />
                <span>Audit Logs</span>
              </div>
            </button>

            <button
              id="nav-diagnostics"
              onClick={() => setActiveTab('diagnostics')}
              className={`w-full flex items-center justify-between px-3 py-2.5 transition-all text-xs ${
                activeTab === 'diagnostics' 
                  ? 'bg-[#3b82f6]/10 text-[#3b82f6] font-semibold border-r-[3px] border-[#3b82f6]' 
                  : 'text-[#94a3b8] hover:text-[#f8fafc] hover:bg-[#1e293b]/60'
              }`}
            >
              <div className="flex items-center space-x-3">
                <Code2 className="w-4 h-4 text-[#3b82f6]" />
                <span>Engine Diagnostics</span>
              </div>
            </button>
          </nav>
        </div>

        {/* User Footer Profile */}
        <div className="p-4 border-t border-[#1e293b] bg-[#020617] flex items-center justify-between text-xs">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-full bg-[#3b82f6] text-white flex items-center justify-center font-bold text-xs">
              AD
            </div>
            <div>
              <div className="font-semibold text-[#f8fafc] truncate">{currentUser.name}</div>
              <div className="text-[10px] text-[#10b981]">System: Operational</div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Header */}
        <header className="h-16 border-b border-[#334155] bg-[#1e293b] px-6 flex items-center justify-between shrink-0 sticky top-0 z-10">
          <div className="flex items-center space-x-4">
            <h2 className="text-sm font-bold text-[#f8fafc] uppercase tracking-wider">
              {activeTab === 'dashboard' && 'Dashboard Overview'}
              {activeTab === 'scans' && 'Vulnerability Scan Engine'}
              {activeTab === 'vulnerabilities' && 'Vulnerability Management Matrix'}
              {activeTab === 'assets' && 'Asset & Host Inventory'}
              {activeTab === 'reports' && 'Executive Security Reports'}
              {activeTab === 'tasks' && 'Remediation Workflow Tasks'}
              {activeTab === 'logs' && 'Security Audit Trail'}
              {activeTab === 'diagnostics' && 'Developer & Engine Diagnostics'}
            </h2>

            <div className="relative hidden lg:block">
              <Search className="w-3.5 h-3.5 text-[#94a3b8] absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search hosts, CVEs..."
                className="bg-[#0f172a] border border-[#334155] rounded-md pl-8 pr-3 py-1.5 text-xs text-white w-64 focus:outline-none focus:border-[#3b82f6]"
              />
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <div className="text-xs text-[#94a3b8] hidden sm:flex items-center space-x-1.5">
              <span>Network:</span>
              <span className="text-[#10b981] font-semibold">Secure</span>
            </div>
            <div className="text-xs text-[#94a3b8] hidden xl:block">
              Host: <code className="text-[#3b82f6] font-mono bg-[#0f172a] px-2 py-0.5 rounded border border-[#334155]">http://0.0.0.0:3000</code>
            </div>
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-1.5 text-[#94a3b8] hover:text-[#f8fafc] rounded-md hover:bg-[#0f172a]"
            >
              {isDarkMode ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </header>

        {/* Dynamic Tab Body */}
        <main className="p-6 flex-1 overflow-y-auto">
          {activeTab === 'dashboard' && (
            <DashboardOverview
              stats={stats}
              assets={assets}
              vulnerabilities={vulnerabilities}
              scans={scans}
              onNavigateTab={(tab) => setActiveTab(tab)}
              onSelectVulnerability={(v) => setSelectedVulnerability(v)}
              onSelectScan={() => setActiveTab('scans')}
              onLaunchScanClick={() => setActiveTab('scans')}
              onDeleteScan={handleDeleteScan}
              onDeleteVulnerability={handleDeleteVulnerability}
              onClearAllScans={handleClearAllScans}
            />
          )}

          {activeTab === 'scans' && (
            <ScanConsole
              onRunScan={handleRunScan}
              onScanCompleted={() => setActiveTab('vulnerabilities')}
              scans={scans}
              onDeleteScan={handleDeleteScan}
            />
          )}

          {activeTab === 'vulnerabilities' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between bg-slate-900 border border-slate-800 p-4 rounded-xl">
                <div>
                  <h3 className="text-lg font-bold text-slate-100">Discovered Vulnerabilities ({vulnerabilities.length})</h3>
                  <p className="text-xs text-slate-400">Click any vulnerability row to view AI analysis, or use the delete button to purge findings.</p>
                </div>

                {vulnerabilities.length > 0 && (
                  <button
                    type="button"
                    onClick={() => {
                      if (window.confirm('Are you sure you want to delete all discovered vulnerability findings?')) {
                        setVulnerabilities([]);
                        setSelectedVulnerability(null);
                      }
                    }}
                    className="bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-semibold px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition-all"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Clear All Findings</span>
                  </button>
                )}
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs text-slate-300">
                    <thead className="bg-slate-950 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                      <tr>
                        <th className="p-3.5">Severity</th>
                        <th className="p-3.5">Title / Flaw</th>
                        <th className="p-3.5">Host / Port</th>
                        <th className="p-3.5">CVE</th>
                        <th className="p-3.5">Status</th>
                        <th className="p-3.5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {vulnerabilities.length === 0 ? (
                        <tr>
                          <td colSpan={6} className="p-8 text-center text-slate-400">
                            No vulnerability findings recorded. Clean scan posture!
                          </td>
                        </tr>
                      ) : (
                        vulnerabilities.map((v) => (
                          <tr
                            key={v.id}
                            onClick={() => setSelectedVulnerability(v)}
                            className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                          >
                            <td className="p-3.5 whitespace-nowrap">
                              <span className={`px-2 py-0.5 font-bold rounded uppercase text-[10px] ${
                                v.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                                v.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                                'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              }`}>
                                {v.severity} ({v.cvssScore})
                              </span>
                            </td>
                            <td className="p-3.5 font-medium text-slate-100 max-w-xs truncate">
                              {v.title}
                            </td>
                            <td className="p-3.5 font-mono text-blue-400 whitespace-nowrap">
                              {v.affectedHost}{v.affectedPort ? `:${v.affectedPort}` : ''}
                            </td>
                            <td className="p-3.5 font-mono text-slate-400 whitespace-nowrap">
                              {v.cveId || 'N/A'}
                            </td>
                            <td className="p-3.5 whitespace-nowrap">
                              <span className={`px-2 py-0.5 rounded text-[11px] ${
                                v.status === 'Fixed' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-300'
                              }`}>
                                {v.status}
                              </span>
                            </td>
                            <td className="p-3.5 text-right whitespace-nowrap">
                              <div className="flex items-center justify-end space-x-2">
                                <button className="text-blue-400 hover:text-blue-300 font-semibold">Inspect →</button>
                                <button
                                  type="button"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleDeleteVulnerability(v.id);
                                  }}
                                  className="p-1 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded transition-colors"
                                  title="Delete finding"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'assets' && (
            <AssetInventory
              assets={assets}
              vulnerabilities={vulnerabilities}
              onSelectAsset={() => setActiveTab('vulnerabilities')}
              onDeleteAsset={handleDeleteAsset}
              onClearAllAssets={handleClearAllAssets}
            />
          )}

          {activeTab === 'reports' && (
            <ReportGenerator
              scans={scans}
              vulnerabilities={vulnerabilities}
              stats={stats}
            />
          )}

          {activeTab === 'tasks' && (
            <div className="space-y-6">
              <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                <h3 className="text-lg font-bold text-slate-100">Remediation Task Tracking</h3>
                <p className="text-xs text-slate-400 mt-1">Assign fix items to DevOps and System Administrators.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {remediationTasks.map((t) => (
                  <div key={t.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded">
                        {t.severity}
                      </span>
                      <span className="text-xs text-slate-400">{t.status}</span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-100">{t.vulnerabilityTitle}</h4>
                    <div className="text-xs text-slate-400">Assignee: <span className="text-slate-200">{t.assignee}</span></div>
                    <div className="text-xs text-slate-400">Due Date: <span className="text-blue-400 font-mono">{new Date(t.dueDate).toLocaleDateString()}</span></div>
                    <p className="text-xs text-slate-300 bg-slate-950 p-2.5 rounded border border-slate-800">{t.notes}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'logs' && (
            <div className="space-y-6">
              <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                <h3 className="text-lg font-bold text-slate-100">Security Audit Logs</h3>
                <p className="text-xs text-slate-400 mt-1">Immutable system actions, scan launches, and login events.</p>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2 font-mono text-xs">
                {activityLogs.map((log) => (
                  <div key={log.id} className="p-3 bg-slate-950 rounded border border-slate-800/80 flex items-center justify-between">
                    <div className="space-x-3">
                      <span className="text-slate-500">{new Date(log.timestamp).toLocaleString()}</span>
                      <span className="text-blue-400 font-bold">{log.user}</span>
                      <span className="text-slate-200">[{log.action}]: {log.details}</span>
                    </div>
                    <span className="text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">{log.category}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'diagnostics' && (
            <DeveloperDiagnostics scans={scans} />
          )}
        </main>
      </div>

      {/* Vulnerability Inspector Modal */}
      <VulnerabilityDetailModal
        vulnerability={selectedVulnerability}
        onClose={() => setSelectedVulnerability(null)}
        onStatusChange={handleVulnerabilityStatusChange}
        onRequestAiAnalysis={handleRequestAiAnalysis}
        isAiLoading={isAiLoading}
        onDeleteVulnerability={handleDeleteVulnerability}
      />
    </div>
  );
}
