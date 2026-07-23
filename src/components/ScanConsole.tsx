import React, { useState } from 'react';
import { 
  Play, Shield, Server, Globe, Cpu, CheckSquare, Square, AlertCircle, RefreshCw, Terminal, Layers, Trash2
} from 'lucide-react';
import { ScanType, ScanPluginConfig, ScanResult } from '../types';

interface ScanConsoleProps {
  onRunScan: (scanParams: {
    target: string;
    scanType: ScanType;
    name: string;
    plugins: ScanPluginConfig;
  }) => Promise<ScanResult>;
  onScanCompleted: (scan: ScanResult) => void;
  scans?: ScanResult[];
  onDeleteScan?: (scanId: string) => void;
}

export const ScanConsole: React.FC<ScanConsoleProps> = ({ onRunScan, onScanCompleted, scans = [], onDeleteScan }) => {
  const [scanType, setScanType] = useState<ScanType>('single');
  const [target, setTarget] = useState('192.168.1.15');
  const [scanName, setScanName] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [scanError, setScanError] = useState<string | null>(null);

  const [plugins, setPlugins] = useState<ScanPluginConfig>({
    nmapPortScan: true,
    niktoWebScan: true,
    whatWebTechScan: true,
    sslAnalysis: true,
    dnsLookup: true,
    whoisLookup: true,
    httpHeaderScan: true,
    osDetection: true,
    serviceDetection: true
  });

  const handleTogglePlugin = (key: keyof ScanPluginConfig) => {
    setPlugins(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;

    setIsScanning(true);
    setProgress(10);
    setCurrentStep('Initializing plugin engine...');

    // Simulate progressive step logs for real-world security assessment feel
    const steps = [
      { p: 25, label: 'Running Nmap Port Scan & Host Discovery...' },
      { p: 45, label: 'Fingerprinting Operating System & Service Versions...' },
      { p: 65, label: 'Executing Nikto Web Scanner & SSL Cryptographic Audit...' },
      { p: 85, label: 'Running WhatWeb Technology Detection & HTTP Header Probes...' },
      { p: 95, label: 'Aggregating Findings & Invoking AI Risk Analysis...' },
      { p: 100, label: 'Scan Completed Successfully!' }
    ];

    for (const step of steps) {
      await new Promise(r => setTimeout(r, 600));
      setProgress(step.p);
      setCurrentStep(step.label);
    }

    try {
      setScanError(null);
      const newScan = await onRunScan({
        target,
        scanType,
        name: scanName || `${scanType.toUpperCase()} Scan - ${target}`,
        plugins
      });
      setIsScanning(false);
      onScanCompleted(newScan);
    } catch (err) {
      setIsScanning(false);
      setScanError('Failed to execute scan. Check backend connection or target configuration.');
    }
  };

  const handlePresetChange = (type: ScanType) => {
    setScanType(type);
    if (type === 'single') setTarget('192.168.1.15');
    if (type === 'network') setTarget('192.168.1.0/24');
    if (type === 'domain') setTarget('example.com');
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-6 shadow-xl space-y-6">
        <div>
          <h2 className="text-lg font-bold text-[#f8fafc] flex items-center space-x-2 uppercase tracking-wide">
            <Shield className="w-5 h-5 text-[#3b82f6]" />
            <span>Vulnerability Scan Launcher</span>
          </h2>
          <p className="text-xs text-[#94a3b8] mt-1">
            Configure target parameters, select modular plugins (Nmap, Nikto, WhatWeb, SSL, DNS), and initiate a security assessment.
          </p>
        </div>

        {scanError && (
          <div className="bg-[#ef4444]/10 border border-[#ef4444]/30 text-[#ef4444] p-3 rounded-md text-xs font-medium flex items-center justify-between">
            <span>{scanError}</span>
            <button onClick={() => setScanError(null)} className="text-[#94a3b8] hover:text-white">✕</button>
          </div>
        )}

        {/* Target Type Selector */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            type="button"
            onClick={() => handlePresetChange('single')}
            className={`p-4 rounded-lg border transition-all text-left flex items-start space-x-3 ${
              scanType === 'single'
                ? 'bg-[#3b82f6]/10 border-[#3b82f6] text-[#f8fafc]'
                : 'bg-[#0f172a] border-[#334155] text-[#94a3b8] hover:border-[#64748b]'
            }`}
          >
            <Server className={`w-5 h-5 ${scanType === 'single' ? 'text-[#3b82f6]' : 'text-[#64748b]'}`} />
            <div>
              <div className="font-semibold text-xs text-[#f8fafc]">Single Host Scan</div>
              <div className="text-[11px] text-[#94a3b8] mt-0.5">Target single IP address (e.g. 192.168.1.15)</div>
            </div>
          </button>

          <button
            type="button"
            onClick={() => handlePresetChange('network')}
            className={`p-4 rounded-lg border transition-all text-left flex items-start space-x-3 ${
              scanType === 'network'
                ? 'bg-[#3b82f6]/10 border-[#3b82f6] text-[#f8fafc]'
                : 'bg-[#0f172a] border-[#334155] text-[#94a3b8] hover:border-[#64748b]'
            }`}
          >
            <Layers className={`w-5 h-5 ${scanType === 'network' ? 'text-[#3b82f6]' : 'text-[#64748b]'}`} />
            <div>
              <div className="font-semibold text-xs text-[#f8fafc]">Network CIDR Scan</div>
              <div className="text-[11px] text-[#94a3b8] mt-0.5">Discover subnet hosts (e.g. 192.168.1.0/24)</div>
            </div>
          </button>

          <button
            type="button"
            onClick={() => handlePresetChange('domain')}
            className={`p-4 rounded-lg border transition-all text-left flex items-start space-x-3 ${
              scanType === 'domain'
                ? 'bg-[#3b82f6]/10 border-[#3b82f6] text-[#f8fafc]'
                : 'bg-[#0f172a] border-[#334155] text-[#94a3b8] hover:border-[#64748b]'
            }`}
          >
            <Globe className={`w-5 h-5 ${scanType === 'domain' ? 'text-[#3b82f6]' : 'text-[#64748b]'}`} />
            <div>
              <div className="font-semibold text-xs text-[#f8fafc]">Domain / Web Edge Scan</div>
              <div className="text-[11px] text-[#94a3b8] mt-0.5">Target FQDN domain (e.g. example.com)</div>
            </div>
          </button>
        </div>

        {/* Scan Input Form */}
        <form onSubmit={handleLaunch} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8] mb-1.5">
                Target IP / CIDR / Domain
              </label>
              <input
                type="text"
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={scanType === 'single' ? '192.168.1.15' : scanType === 'network' ? '192.168.1.0/24' : 'example.com'}
                className="w-full bg-[#0f172a] border border-[#334155] rounded-md px-3.5 py-2 text-xs text-[#f8fafc] focus:outline-none focus:border-[#3b82f6] font-mono"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8] mb-1.5">
                Assessment Name (Optional)
              </label>
              <input
                type="text"
                value={scanName}
                onChange={(e) => setScanName(e.target.value)}
                placeholder="e.g. Q3 Subnet Security Assessment"
                className="w-full bg-[#0f172a] border border-[#334155] rounded-md px-3.5 py-2 text-xs text-[#f8fafc] focus:outline-none focus:border-[#3b82f6]"
              />
            </div>
          </div>

          {/* Plugin Selection Module */}
          <div className="bg-[#0f172a] border border-[#334155] rounded-lg p-4 space-y-3">
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#94a3b8] flex items-center space-x-2">
              <Cpu className="w-4 h-4 text-[#3b82f6]" />
              <span>Integrated Scanner Plugins</span>
            </h3>
            
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {[
                { id: 'nmapPortScan', label: 'Nmap Port Scan', desc: 'SYN/TCP Connect scanning' },
                { id: 'osDetection', label: 'OS Detection', desc: 'TCP/IP stack fingerprinting' },
                { id: 'serviceDetection', label: 'Service Versioning', desc: 'Banner grabbing & probing' },
                { id: 'niktoWebScan', label: 'Nikto Vulnerability Scanner', desc: '6700+ dangerous file checks' },
                { id: 'whatWebTechScan', label: 'WhatWeb Tech Scanner', desc: 'CMS & web server stack detection' },
                { id: 'sslAnalysis', label: 'SSL/TLS Cryptographic Audit', desc: 'Cipher suite & heartbleed check' },
                { id: 'httpHeaderScan', label: 'HTTP Security Headers', desc: 'HSTS, CSP, X-Frame-Options' },
                { id: 'dnsLookup', label: 'DNS Enumeration', desc: 'A, MX, NS, TXT record mapping' },
                { id: 'whoisLookup', label: 'WHOIS Registration Data', desc: 'Registrar & domain owner info' },
              ].map((plugin) => {
                const key = plugin.id as keyof ScanPluginConfig;
                const isChecked = plugins[key];
                return (
                  <button
                    type="button"
                    key={plugin.id}
                    onClick={() => handleTogglePlugin(key)}
                    className={`p-3 rounded-md border text-left transition-all flex items-start space-x-2.5 ${
                      isChecked
                        ? 'bg-[#1e293b] border-[#3b82f6]/50 text-[#f8fafc]'
                        : 'bg-[#0f172a] border-[#334155]/60 text-[#64748b] opacity-60'
                    }`}
                  >
                    {isChecked ? (
                      <CheckSquare className="w-4 h-4 text-[#3b82f6] shrink-0 mt-0.5" />
                    ) : (
                      <Square className="w-4 h-4 text-[#64748b] shrink-0 mt-0.5" />
                    )}
                    <div>
                      <div className="text-xs font-semibold">{plugin.label}</div>
                      <div className="text-[10px] text-[#94a3b8]">{plugin.desc}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Progress / Status Bar during Active Scan */}
          {isScanning && (
            <div className="bg-[#0f172a] border border-[#3b82f6]/30 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-[#3b82f6] font-medium flex items-center space-x-2">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>{currentStep}</span>
                </span>
                <span className="font-mono text-[#f8fafc] font-bold">{progress}%</span>
              </div>
              <div className="w-full bg-[#1e293b] rounded-full h-2 overflow-hidden border border-[#334155]">
                <div 
                  className="bg-[#3b82f6] h-full rounded-full transition-all duration-300" 
                  style={{ width: `${progress}%` }} 
                />
              </div>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <div className="flex items-center space-x-2 text-xs text-[#94a3b8]">
              <AlertCircle className="w-4 h-4 text-[#eab308] shrink-0" />
              <span>Permission Notice: Ensure explicit authorization before scanning networks.</span>
            </div>

            <button
              type="submit"
              disabled={isScanning}
              className="bg-[#3b82f6] hover:bg-blue-600 disabled:opacity-50 text-white font-semibold px-5 py-2 rounded-md shadow flex items-center space-x-2 transition-all text-xs"
            >
              {isScanning ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Running Scan...</span>
                </>
              ) : (
                <>
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Start Security Assessment</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Target History & Delete Management Section */}
      {scans.length > 0 && (
        <div className="bg-[#1e293b] border border-[#334155] rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#334155] pb-3">
            <div>
              <h3 className="text-sm font-bold text-[#f8fafc]">Active Scan Targets & Reports ({scans.length})</h3>
              <p className="text-xs text-[#94a3b8]">Delete a target scan to permanently remove its findings and clean up your dashboard.</p>
            </div>
          </div>

          <div className="space-y-3">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className="p-4 bg-[#0f172a] border border-[#334155] rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-xs text-[#f8fafc]">{scan.name}</span>
                    <span className="px-2 py-0.5 text-[10px] bg-[#1e293b] text-[#3b82f6] rounded uppercase font-semibold border border-[#3b82f6]/30">
                      {scan.scanType}
                    </span>
                    <span className="text-xs text-[#10b981] font-mono bg-[#10b981]/10 px-2 py-0.5 rounded">
                      Risk: {scan.riskScore}/100
                    </span>
                  </div>
                  <div className="text-xs text-[#94a3b8] flex items-center space-x-3">
                    <span>Target IP: <code className="text-[#3b82f6] font-mono">{scan.target}</code></span>
                    <span>•</span>
                    <span>Discovered Vulnerabilities: <strong className="text-white">{scan.vulnerabilities?.length || 0}</strong></span>
                    <span>•</span>
                    <span>Date: {new Date(scan.startTime).toLocaleString()}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  {onDeleteScan && (
                    <button
                      type="button"
                      onClick={() => {
                        if (window.confirm(`Delete scan for IP ${scan.target}? All vulnerability findings and reports associated with this target will be purged.`)) {
                          onDeleteScan(scan.id);
                        }
                      }}
                      className="bg-[#ef4444]/10 hover:bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30 text-xs font-semibold px-3 py-1.5 rounded-md flex items-center space-x-1.5 transition-all"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Delete Scan & Reports</span>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
