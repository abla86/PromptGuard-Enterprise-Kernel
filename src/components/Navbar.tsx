import React from 'react';
import {
  ShieldCheck,
  Cpu,
  Layers,
  Terminal,
  Activity,
  Zap,
  Code2,
  Sliders,
  Sparkles,
  GitBranch,
} from 'lucide-react';

interface NavbarProps {
  activeTab: 'inspector' | 'tests' | 'taint-graph' | 'fuzzer' | 'python-source';
  setActiveTab: (tab: 'inspector' | 'tests' | 'taint-graph' | 'fuzzer' | 'python-source') => void;
  onOpenConfig: () => void;
  totalTestsCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  onOpenConfig,
  totalTestsCount,
}) => {
  return (
    <header className="border-b border-[#27272A] bg-[#09090B]/95 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Identity */}
          <div className="flex items-center space-x-3.5">
            <div className="w-9 h-9 bg-[#18181B] border border-[#3F3F46] rounded flex items-center justify-center">
              <div className="w-4 h-4 border-2 border-[#10B981] rounded-xs flex items-center justify-center">
                <div className="w-1.5 h-1.5 bg-[#10B981] rounded-xs"></div>
              </div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-base sm:text-lg font-bold tracking-tight text-[#FAFAFA] font-sans">
                  PROMPTGUARD <span className="text-[#10B981]">ENTERPRISE KERNEL</span>
                </h1>
                <span className="text-[9px] uppercase tracking-[0.15em] font-mono px-1.5 py-0.5 rounded bg-[#18181B] text-[#A1A1AA] border border-[#27272A]">
                  v4.2.1
                </span>
              </div>
              <p className="text-[10px] text-[#71717A] uppercase tracking-[0.18em] hidden sm:block font-mono">
                Deterministic AI Firewall & Taint Tracking
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center space-x-1 sm:space-x-1.5">
            <button
              id="nav-tab-inspector"
              onClick={() => setActiveTab('inspector')}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center space-x-1.5 ${
                activeTab === 'inspector'
                  ? 'bg-[#18181B] text-[#10B981] border border-[#3F3F46] font-bold'
                  : 'text-[#A1A1AA] hover:text-[#FAFAFA] hover:bg-[#18181B]/50 border border-transparent'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Inspector</span>
            </button>

            <button
              id="nav-tab-tests"
              onClick={() => setActiveTab('tests')}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center space-x-1.5 ${
                activeTab === 'tests'
                  ? 'bg-[#18181B] text-[#10B981] border border-[#3F3F46] font-bold'
                  : 'text-[#A1A1AA] hover:text-[#FAFAFA] hover:bg-[#18181B]/50 border border-transparent'
              }`}
            >
              <Zap className="w-3.5 h-3.5 text-[#10B981]" />
              <span>Test Suite</span>
              <span className="px-1.5 py-0.2 rounded text-[9px] bg-[#09090B] text-[#71717A] border border-[#27272A]">
                {totalTestsCount}
              </span>
            </button>

            <button
              id="nav-tab-taint-graph"
              onClick={() => setActiveTab('taint-graph')}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center space-x-1.5 ${
                activeTab === 'taint-graph'
                  ? 'bg-[#18181B] text-[#10B981] border border-[#3F3F46] font-bold'
                  : 'text-[#A1A1AA] hover:text-[#FAFAFA] hover:bg-[#18181B]/50 border border-transparent'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5 text-[#3B82F6]" />
              <span className="hidden md:inline">Taint Graph</span>
              <span className="md:hidden">Graph</span>
            </button>

            <button
              id="nav-tab-fuzzer"
              onClick={() => setActiveTab('fuzzer')}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center space-x-1.5 ${
                activeTab === 'fuzzer'
                  ? 'bg-[#18181B] text-[#10B981] border border-[#3F3F46] font-bold'
                  : 'text-[#A1A1AA] hover:text-[#FAFAFA] hover:bg-[#18181B]/50 border border-transparent'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5 text-[#F59E0B]" />
              <span className="hidden lg:inline">Attack Fuzzer</span>
              <span className="lg:hidden">Fuzzer</span>
            </button>

            <button
              id="nav-tab-source"
              onClick={() => setActiveTab('python-source')}
              className={`px-3 py-1.5 rounded text-xs font-mono transition-all flex items-center space-x-1.5 ${
                activeTab === 'python-source'
                  ? 'bg-[#18181B] text-[#10B981] border border-[#3F3F46] font-bold'
                  : 'text-[#A1A1AA] hover:text-[#FAFAFA] hover:bg-[#18181B]/50 border border-transparent'
              }`}
            >
              <Code2 className="w-3.5 h-3.5 text-[#A1A1AA]" />
              <span className="hidden lg:inline">promptguard_kernel.py</span>
              <span className="lg:hidden">Python</span>
            </button>
          </nav>

          {/* Right Action Controls & Status */}
          <div className="flex items-center space-x-3">
            <div className="hidden sm:flex items-center space-x-2 bg-[#18181B] border border-[#27272A] px-2.5 py-1 rounded">
              <div className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse"></div>
              <span className="text-[11px] font-mono text-[#A1A1AA] uppercase">Kernel: Active</span>
            </div>

            <button
              id="btn-engine-config"
              onClick={onOpenConfig}
              className="px-2.5 py-1.5 rounded border border-[#27272A] bg-[#18181B] text-[#A1A1AA] hover:text-[#FAFAFA] hover:border-[#3F3F46] transition-colors flex items-center space-x-1.5 text-xs font-mono"
              title="Configure Firewall Policies"
            >
              <Sliders className="w-3.5 h-3.5 text-[#10B981]" />
              <span className="hidden sm:inline">Config</span>
            </button>
          </div>
        </div>
      </div>

      {/* Defense Layer Sub-Bar */}
      <div className="bg-[#09090B] border-t border-[#27272A] px-4 py-1.5 overflow-x-auto text-[11px] text-[#71717A] flex items-center justify-between">
        <div className="max-w-7xl mx-auto w-full flex items-center justify-between space-x-4">
          <div className="flex items-center space-x-3 shrink-0">
            <span className="font-mono text-[#71717A] font-bold uppercase tracking-wider text-[10px]">Defense Pipeline:</span>
            <span className="flex items-center space-x-1 text-[#E4E4E7]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#10B981] inline-block animate-pulse"></span>
              <span>1. De-cloaking</span>
            </span>
            <span className="text-[#3F3F46]">→</span>
            <span className="text-[#E4E4E7]">2. Recursive Decode</span>
            <span className="text-[#3F3F46]">→</span>
            <span className="text-[#E4E4E7]">3. Delimiters & Pattern Matrix</span>
            <span className="text-[#3F3F46]">→</span>
            <span className="text-[#E4E4E7]">4. AST Auditor</span>
            <span className="text-[#3F3F46]">→</span>
            <span className="text-[#E4E4E7]">5. Taint Provenance</span>
          </div>
          <div className="hidden md:flex items-center space-x-2 text-[#71717A] font-mono text-[10px] tracking-wider uppercase">
            <span>Deterministic Runtime</span>
            <span>•</span>
            <span className="text-[#10B981] font-semibold">Zero-Dependency</span>
          </div>
        </div>
      </div>
    </header>
  );
};
