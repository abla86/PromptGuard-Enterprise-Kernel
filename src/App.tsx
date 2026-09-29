import React, { useState, useMemo, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { LiveFirewallInspector } from './components/LiveFirewallInspector';
import { TestSuiteRunner } from './components/TestSuiteRunner';
import { TaintGraphVisualizer } from './components/TaintGraphVisualizer';
import { PayloadFuzzerBuilder } from './components/PayloadFuzzerBuilder';
import { PythonCodeViewer } from './components/PythonCodeViewer';
import { EngineConfigModal } from './components/EngineConfigModal';
import { SignedAuditModal } from './components/SignedAuditModal';
import { PromptGuardEngine } from './engine/taintEngine';
import { auditSession } from './engine/auditSession';
import { INITIAL_TEST_VECTORS } from './data/testVectors';
import { TrustLevel } from './types';
import { ShieldCheck, ShieldAlert, Cpu, Terminal, Sparkles, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<
    'inspector' | 'tests' | 'taint-graph' | 'fuzzer' | 'python-source'
  >('inspector');

  const [isConfigOpen, setIsConfigOpen] = useState<boolean>(false);
  const [isAuditModalOpen, setIsAuditModalOpen] = useState<boolean>(false);
  const [engineVersionKey, setEngineVersionKey] = useState<number>(0);
  const [auditEventsCount, setAuditEventsCount] = useState<number>(auditSession.getEvents().length);

  // External trigger for live inspector
  const [inspectorState, setInspectorState] = useState<{
    payload?: string;
    trust?: TrustLevel;
    toolId?: string;
  }>({});

  // Singleton PromptGuard Engine instance
  const engine = useMemo(() => new PromptGuardEngine(), []);

  // Listen to auditSession log updates
  useEffect(() => {
    const unsubscribe = auditSession.subscribe(() => {
      setAuditEventsCount(auditSession.getEvents().length);
    });
    return unsubscribe;
  }, []);

  // Seed session logs on initial load if empty
  useEffect(() => {
    if (auditSession.getEvents().length === 0) {
      INITIAL_TEST_VECTORS.slice(0, 5).forEach((vector) => {
        const res = engine.inspectAndContain(vector.payload, vector.trust, vector.targetTool);
        auditSession.logInspection(res, 'test_suite', vector.targetTool);
      });
    }
  }, [engine]);

  const handleConfigChanged = () => {
    setEngineVersionKey((prev) => prev + 1);
  };

  const handleSendFuzzedToInspector = (payload: string, trust: TrustLevel) => {
    setInspectorState({ payload, trust, toolId: 'tool_search_db' });
    setActiveTab('inspector');
  };

  const handleSelectEventForInspector = (payload: string, trust: TrustLevel, toolId?: string) => {
    setInspectorState({ payload, trust, toolId });
    setActiveTab('inspector');
  };

  return (
    <div className="min-h-screen bg-[#09090B] text-[#FAFAFA] flex flex-col font-sans selection:bg-[#10B981]/30 selection:text-[#10B981]">
      {/* Top Navigation Bar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenConfig={() => setIsConfigOpen(true)}
        onOpenAuditModal={() => setIsAuditModalOpen(true)}
        auditEventsCount={auditEventsCount}
        totalTestsCount={INITIAL_TEST_VECTORS.length}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {activeTab === 'inspector' && (
          <LiveFirewallInspector
            key={engineVersionKey}
            engine={engine}
            onOpenAuditModal={() => setIsAuditModalOpen(true)}
            initialPayload={inspectorState.payload}
            initialTrust={inspectorState.trust}
            initialToolId={inspectorState.toolId}
          />
        )}

        {activeTab === 'tests' && (
          <TestSuiteRunner
            key={engineVersionKey}
            engine={engine}
            onOpenAuditModal={() => setIsAuditModalOpen(true)}
          />
        )}

        {activeTab === 'taint-graph' && (
          <TaintGraphVisualizer
            key={engineVersionKey}
            engine={engine}
            onOpenAuditModal={() => setIsAuditModalOpen(true)}
          />
        )}

        {activeTab === 'fuzzer' && (
          <PayloadFuzzerBuilder
            key={engineVersionKey}
            engine={engine}
            onSendToInspector={handleSendFuzzedToInspector}
          />
        )}

        {activeTab === 'python-source' && <PythonCodeViewer />}
      </main>

      {/* Enterprise Architectural Footer */}
      <footer className="border-t border-[#27272A] bg-[#09090B] py-5 mt-12 text-[10px] text-[#71717A] uppercase tracking-[0.2em] font-mono">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2.5">
            <div className="w-1.5 h-1.5 rounded-full bg-[#10B981]"></div>
            <span className="text-[#A1A1AA] font-bold">
              PROMPTGUARD_V4_SECURE_KERNEL_ISO_9001
            </span>
            <span>—</span>
            <span>Deterministic 5-Layer AI Firewall</span>
          </div>

          <div className="flex items-center space-x-4 text-[10px]">
            <span className="text-[#A1A1AA]">SIGNATURE: ECDSA-P256-SHA256 (RFC 8785)</span>
            <span>•</span>
            <span className="text-[#10B981] font-semibold">ZERO-DEP DETERMINISTIC</span>
          </div>
        </div>
      </footer>

      {/* Engine Configuration Modal */}
      <EngineConfigModal
        engine={engine}
        isOpen={isConfigOpen}
        onClose={() => setIsConfigOpen(false)}
        onConfigChanged={handleConfigChanged}
      />

      {/* Signed JSON Audit Report & Verification Modal */}
      <SignedAuditModal
        isOpen={isAuditModalOpen}
        onClose={() => setIsAuditModalOpen(false)}
        engine={engine}
        onSelectEventForInspector={handleSelectEventForInspector}
      />
    </div>
  );
}
