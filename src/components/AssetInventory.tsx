import React, { useState } from 'react';
import { 
  Server, Shield, Search, Filter, Cpu, CheckCircle2, AlertTriangle, ChevronRight, Tag, Activity, Trash2
} from 'lucide-react';
import { Asset, Vulnerability } from '../types';

interface AssetInventoryProps {
  assets: Asset[];
  vulnerabilities: Vulnerability[];
  onSelectAsset: (asset: Asset) => void;
  onDeleteAsset?: (assetId: string) => void;
  onClearAllAssets?: () => void;
}

export const AssetInventory: React.FC<AssetInventoryProps> = ({ 
  assets, 
  vulnerabilities, 
  onSelectAsset,
  onDeleteAsset,
  onClearAllAssets
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');

  const filteredAssets = assets.filter(asset => {
    const matchesSearch = asset.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          asset.ip.includes(searchQuery) ||
                          asset.tags.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesCategory = selectedCategory === 'All' || asset.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#1e293b] border border-[#334155] p-5 rounded-lg">
        <div>
          <h2 className="text-lg font-bold text-[#f8fafc] flex items-center space-x-2 uppercase tracking-wide">
            <Server className="w-5 h-5 text-[#3b82f6]" />
            <span>Asset Inventory & Subnet Host Map ({assets.length})</span>
          </h2>
          <p className="text-xs text-[#94a3b8] mt-0.5">
            Track host hardware, operating systems, open listening ports, and risk index across network infrastructure.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#94a3b8] absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filter IP, hostname, tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#0f172a] border border-[#334155] rounded-md pl-8 pr-3 py-1.5 text-xs text-[#f8fafc] focus:outline-none focus:border-[#3b82f6] w-52"
            />
          </div>

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-[#0f172a] border border-[#334155] rounded-md px-3 py-1.5 text-xs text-[#f8fafc] focus:outline-none focus:border-[#3b82f6]"
          >
            <option value="All">All Categories</option>
            <option value="Server">Server</option>
            <option value="Network Device">Network Device</option>
            <option value="Web App">Web App</option>
            <option value="Cloud Resource">Cloud Resource</option>
          </select>

          {assets.length > 0 && onClearAllAssets && (
            <button
              onClick={onClearAllAssets}
              className="bg-[#ef4444]/10 hover:bg-[#ef4444]/20 text-[#ef4444] border border-[#ef4444]/30 font-semibold px-3 py-1.5 rounded-md text-xs flex items-center space-x-1.5 transition-all shrink-0"
              title="Delete all assets from inventory"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Inventory</span>
            </button>
          )}
        </div>
      </div>

      {/* Asset Cards Grid */}
      {filteredAssets.length === 0 ? (
        <div className="bg-[#1e293b] border border-[#334155] rounded-lg p-12 text-center text-xs text-[#94a3b8]">
          <Server className="w-10 h-10 text-[#64748b] mx-auto mb-3 opacity-50" />
          <p className="font-semibold text-sm text-[#f8fafc]">No Assets Found in Inventory</p>
          <p className="mt-1 text-[#94a3b8]">Launch network scans to discover active hosts or run new assessment scans.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredAssets.map((asset) => (
            <div
              key={asset.id}
              onClick={() => onSelectAsset(asset)}
              className="bg-[#1e293b] border border-[#334155] hover:border-[#3b82f6]/50 rounded-lg p-5 cursor-pointer transition-all space-y-4 group flex flex-col justify-between"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-[#3b82f6] font-bold bg-[#0f172a] px-2 py-0.5 rounded border border-[#334155]">
                    {asset.ip}
                  </span>
                  <div className="flex items-center space-x-2">
                    <span className={`text-[10px] px-2 py-0.5 rounded font-semibold uppercase ${
                      asset.status === 'Online' ? 'bg-[#10b981]/10 text-[#10b981] border border-[#10b981]/20' : 'bg-[#0f172a] text-[#94a3b8]'
                    }`}>
                      {asset.status}
                    </span>
                    {onDeleteAsset && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm(`Delete asset ${asset.hostname} (${asset.ip}) from inventory?`)) {
                            onDeleteAsset(asset.id);
                          }
                        }}
                        className="p-1 text-[#94a3b8] hover:text-[#ef4444] hover:bg-[#0f172a] rounded transition-colors"
                        title="Delete asset from inventory"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                <h3 className="text-sm font-bold text-[#f8fafc] group-hover:text-[#3b82f6] transition-colors">
                  {asset.hostname}
                </h3>

                <div className="text-xs text-[#94a3b8] flex items-center space-x-2">
                  <Cpu className="w-3.5 h-3.5 text-[#64748b] shrink-0" />
                  <span className="truncate">{asset.os}</span>
                </div>
              </div>

              <div className="space-y-3 pt-2 border-t border-[#334155]">
                {/* Vulnerabilities Pill Badges */}
                <div className="flex items-center space-x-1.5 text-[10px]">
                  {asset.vulnerabilitiesCount.critical > 0 && (
                    <span className="bg-[#ef4444]/20 text-[#ef4444] px-1.5 py-0.5 rounded font-bold border border-[#ef4444]/30">
                      {asset.vulnerabilitiesCount.critical} Crit
                    </span>
                  )}
                  {asset.vulnerabilitiesCount.high > 0 && (
                    <span className="bg-[#f97316]/20 text-[#f97316] px-1.5 py-0.5 rounded font-bold border border-[#f97316]/30">
                      {asset.vulnerabilitiesCount.high} High
                    </span>
                  )}
                  {asset.vulnerabilitiesCount.medium > 0 && (
                    <span className="bg-[#eab308]/20 text-[#eab308] px-1.5 py-0.5 rounded font-bold border border-[#eab308]/30">
                      {asset.vulnerabilitiesCount.medium} Med
                    </span>
                  )}
                  {asset.vulnerabilitiesCount.critical === 0 && asset.vulnerabilitiesCount.high === 0 && asset.vulnerabilitiesCount.medium === 0 && (
                    <span className="bg-[#10b981]/10 text-[#10b981] px-1.5 py-0.5 rounded font-bold border border-[#10b981]/20">
                      Clean
                    </span>
                  )}
                </div>

                {/* Tags */}
                <div className="flex flex-wrap gap-1">
                  {asset.tags.map((t, idx) => (
                    <span key={idx} className="text-[10px] bg-[#0f172a] text-[#94a3b8] px-2 py-0.5 rounded border border-[#334155] flex items-center space-x-1">
                      <Tag className="w-2.5 h-2.5" />
                      <span>{t}</span>
                    </span>
                  ))}
                </div>

                {/* Footer Risk Meter */}
                <div className="flex items-center justify-between text-xs pt-1">
                  <span className="text-[#94a3b8]">Risk Score</span>
                  <span className={`font-bold font-mono ${
                    asset.riskScore > 80 ? 'text-[#ef4444]' : asset.riskScore > 50 ? 'text-[#eab308]' : 'text-[#10b981]'
                  }`}>
                    {asset.riskScore} / 100
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

