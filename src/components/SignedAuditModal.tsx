import React, { useState, useEffect, useMemo } from 'react';
import {
  FileText,
  Download,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  Key,
  Lock,
  RotateCcw,
  Sparkles,
  ExternalLink,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  X,
  FileCheck,
  Fingerprint,
  Cpu,
  Layers,
  Terminal,
  Database,
  Eye,
  Sliders,
} from 'lucide-react';
import {
  auditSession,
  AuditInspectionEvent,
  SignedAuditReportDocument,
} from '../engine/auditSession';
import {
  getOrCreateSessionKeyPair,
  verifyAuditReportJson,
  VerificationResult,
} from '../engine/cryptoSigner';
import { PromptGuardEngine } from '../engine/taintEngine';
import { EnforcementAction, TrustLevel } from '../types';

interface SignedAuditModalProps {
  isOpen: boolean;
  onClose: () => void;
  engine: PromptGuardEngine;
  onSelectEventForInspector?: (payload: string, trust: TrustLevel, toolId?: string) => void;
}

export const SignedAuditModal: React.FC<SignedAuditModalProps> = ({
  isOpen,
  onClose,
  engine,
  onSelectEventForInspector,
}) => {
  const [activeTab, setActiveTab] = useState<'export' | 'verify' | 'logs'>('export');
  const [events, setEvents] = useState<AuditInspectionEvent[]>(auditSession.getEvents());
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [signedDoc, setSignedDoc] = useState<SignedAuditReportDocument | null>(null);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [keyId, setKeyId] = useState<string>('');
  const [publicKeyPem, setPublicKeyPem] = useState<string>('');

  // Export options
  const [includeFullPayloads, setIncludeFullPayloads] = useState<boolean>(true);
  const [organizationName, setOrganizationName] = useState<string>(
    'Enterprise SecOps & AI Safety Operations'
  );
  const [auditorNotes, setAuditorNotes] = useState<string>(
    'Deterministic firewall kernel session logs and taint provenance audit verification'
  );

  // Verification state
  const [verifyInputJson, setVerifyInputJson] = useState<string>('');
  const [verificationResult, setVerificationResult] = useState<VerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);

  // Logs search and filter
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterAction, setFilterAction] = useState<'ALL' | 'BLOCK' | 'SANITIZE' | 'ALLOW'>('ALL');
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

  // Listen to auditSession updates
  useEffect(() => {
    const unsubscribe = auditSession.subscribe(() => {
      setEvents(auditSession.getEvents());
    });
    return unsubscribe;
  }, []);

  // Load key pair metadata on mount/open
  useEffect(() => {
    if (isOpen) {
      getOrCreateSessionKeyPair().then((kp) => {
        setKeyId(kp.keyId);
        setPublicKeyPem(kp.publicKeyPem);
      });
      refreshSignedReport();
    }
  }, [isOpen, includeFullPayloads, organizationName, auditorNotes]);

  const refreshSignedReport = async () => {
    setIsGenerating(true);
    try {
      const { signedReport } = await auditSession.generateSignedAuditReport(
        engine.getConfig(),
        {
          includeFullPayloads,
          organizationName,
          auditorNotes,
        }
      );
      setSignedDoc(signedReport);
    } catch (err) {
      console.error('Error generating signed audit report:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownloadJson = () => {
    if (!signedDoc) return;
    const jsonStr = JSON.stringify(signedDoc, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const dateStr = new Date().toISOString().slice(0, 10);
    a.download = `promptguard_signed_audit_report_${dateStr}_${signedDoc.report_header.report_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopyJson = () => {
    if (!signedDoc) return;
    navigator.clipboard.writeText(JSON.stringify(signedDoc, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  const handleCopyPublicKey = () => {
    navigator.clipboard.writeText(publicKeyPem);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleVerifyPastedJson = async () => {
    if (!verifyInputJson.trim()) return;
    setIsVerifying(true);
    try {
      const parsed = JSON.parse(verifyInputJson);
      const res = await verifyAuditReportJson(parsed);
      setVerificationResult(res);
    } catch (err: any) {
      setVerificationResult({
        isValid: false,
        algorithm: 'UNKNOWN',
        keyId: 'NONE',
        signedAt: '',
        digestMatch: false,
        computedDigestSha256: '',
        reportDigestSha256: '',
        error: `Invalid JSON syntax: ${err.message}`,
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleLoadCurrentIntoVerifier = () => {
    if (signedDoc) {
      setVerifyInputJson(JSON.stringify(signedDoc, null, 2));
      verifyAuditReportJson(signedDoc).then(setVerificationResult);
    }
  };

  const handleClearLogs = () => {
    auditSession.clearLogs();
    setEvents([]);
    refreshSignedReport();
  };

  // Filtered session logs
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (filterAction === 'BLOCK' && evt.action !== EnforcementAction.BLOCK) return false;
      if (filterAction === 'SANITIZE' && evt.action !== EnforcementAction.SANITIZE_AND_WRAP)
        return false;
      if (filterAction === 'ALLOW' && evt.action !== EnforcementAction.ALLOW) return false;

      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return (
        evt.rawPayload.toLowerCase().includes(q) ||
        evt.eventId.toLowerCase().includes(q) ||
        evt.trustLevelLabel.toLowerCase().includes(q) ||
        (evt.targetToolName && evt.targetToolName.toLowerCase().includes(q)) ||
        evt.violations.some(
          (v) => v.rule_id.toLowerCase().includes(q) || v.description.toLowerCase().includes(q)
        )
      );
    });
  }, [events, filterAction, searchQuery]);

  const metrics = auditSession.getMetrics();

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#18181B] border border-[#27272A] w-full max-w-5xl rounded-xl shadow-2xl flex flex-col max-h-[92vh] overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-[#27272A] flex items-center justify-between bg-[#09090B]">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 bg-[#18181B] border border-[#3F3F46] rounded flex items-center justify-center">
              <FileCheck className="w-5 h-5 text-[#10B981]" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-sm sm:text-base font-bold text-[#FAFAFA] font-mono tracking-tight">
                  AUDIT LOGS & SIGNED JSON REPORT
                </h2>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40 font-mono font-bold">
                  ECDSA P-256
                </span>
              </div>
              <p className="text-[11px] text-[#71717A] font-mono mt-0.5">
                Deterministic RFC 8785 canonicalization with digital tamper-evident signature
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={onClose}
              className="p-1.5 rounded text-[#71717A] hover:text-[#FAFAFA] hover:bg-[#27272A] transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="border-b border-[#27272A] bg-[#09090B] px-4 sm:px-5 flex items-center justify-between">
          <div className="flex space-x-2">
            <button
              onClick={() => setActiveTab('export')}
              className={`py-3 px-3.5 text-xs font-mono border-b-2 font-bold transition-all flex items-center space-x-2 ${
                activeTab === 'export'
                  ? 'border-[#10B981] text-[#10B981]'
                  : 'border-transparent text-[#71717A] hover:text-[#FAFAFA]'
              }`}
            >
              <Download className="w-3.5 h-3.5" />
              <span>Signed Report Export</span>
            </button>

            <button
              onClick={() => setActiveTab('logs')}
              className={`py-3 px-3.5 text-xs font-mono border-b-2 font-bold transition-all flex items-center space-x-2 ${
                activeTab === 'logs'
                  ? 'border-[#10B981] text-[#10B981]'
                  : 'border-transparent text-[#71717A] hover:text-[#FAFAFA]'
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-[#3B82F6]" />
              <span>Session Logs</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#18181B] text-[#A1A1AA] border border-[#27272A]">
                {events.length}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('verify')}
              className={`py-3 px-3.5 text-xs font-mono border-b-2 font-bold transition-all flex items-center space-x-2 ${
                activeTab === 'verify'
                  ? 'border-[#10B981] text-[#10B981]'
                  : 'border-transparent text-[#71717A] hover:text-[#FAFAFA]'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5 text-[#F59E0B]" />
              <span>Verify Signature</span>
            </button>
          </div>

          <div className="hidden sm:flex items-center space-x-3 text-xs font-mono text-[#71717A]">
            <span>Key: <strong className="text-[#FAFAFA]">{keyId || 'Loading...'}</strong></span>
          </div>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 bg-[#09090B]">
          {/* TAB 1: EXPORT SIGNED AUDIT REPORT */}
          {activeTab === 'export' && (
            <div className="space-y-6">
              {/* Quick Summary Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-3">
                  <div className="text-[10px] uppercase font-mono text-[#71717A]">Total Ingress Events</div>
                  <div className="text-xl font-bold font-mono text-[#FAFAFA] mt-1">
                    {metrics.totalInspections}
                  </div>
                  <div className="text-[10px] text-[#71717A] font-mono mt-0.5">
                    Session ID: {metrics.sessionId.slice(-8)}
                  </div>
                </div>

                <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-3">
                  <div className="text-[10px] uppercase font-mono text-[#71717A]">Enforcement: Blocked</div>
                  <div className="text-xl font-bold font-mono text-[#F43F5E] mt-1">
                    {metrics.blockedCount}
                  </div>
                  <div className="text-[10px] text-[#71717A] font-mono mt-0.5">
                    {metrics.totalInspections > 0
                      ? `${((metrics.blockedCount / metrics.totalInspections) * 100).toFixed(0)}% blocked`
                      : '0%'}
                  </div>
                </div>

                <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-3">
                  <div className="text-[10px] uppercase font-mono text-[#71717A]">Taint Violations</div>
                  <div className="text-xl font-bold font-mono text-[#F59E0B] mt-1">
                    {metrics.taintViolationsCount}
                  </div>
                  <div className="text-[10px] text-[#71717A] font-mono mt-0.5">
                    Zero-Trust Barrier Tripped
                  </div>
                </div>

                <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-3">
                  <div className="text-[10px] uppercase font-mono text-[#71717A]">Signing Algorithm</div>
                  <div className="text-sm font-bold font-mono text-[#10B981] mt-1 truncate">
                    ECDSA P-256
                  </div>
                  <div className="text-[10px] text-[#71717A] font-mono mt-0.5">
                    RFC 8785 Canonical
                  </div>
                </div>
              </div>

              {/* Export Customization Options */}
              <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 space-y-4">
                <div className="flex items-center justify-between border-b border-[#27272A] pb-2">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-[#A1A1AA] flex items-center space-x-2">
                    <Sliders className="w-3.5 h-3.5 text-[#10B981]" />
                    <span>Report Generation Metadata & Privacy Controls</span>
                  </h3>
                  <button
                    onClick={refreshSignedReport}
                    className="text-xs text-[#71717A] hover:text-[#FAFAFA] flex items-center space-x-1 font-mono transition-colors"
                  >
                    <RotateCcw className="w-3 h-3" />
                    <span>Re-sign</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-[11px] font-bold uppercase tracking-wider text-[#71717A] font-mono mb-1">
                      Organization / Auditor Entity
                    </label>
                    <input
                      type="text"
                      value={organizationName}
                      onChange={(e) => setOrganizationName(e.target.value)}
                      className="w-full bg-[#09090B] border border-[#27272A] rounded px-3 py-1.5 text-xs font-mono text-[#FAFAFA] focus:border-[#10B981] focus:ring-1 focus:ring-[#10B981]"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase tracking-wider text-[#71717A] font-mono mb-1">
                      Auditor Notes / Compliance Case ID
                    </label>
                    <input
                      type="text"
                      value={auditorNotes}
                      onChange={(e) => setAuditorNotes(e.target.value)}
                      className="w-full bg-[#09090B] border border-[#27272A] rounded px-3 py-1.5 text-xs font-mono text-[#FAFAFA] focus:border-[#10B981] focus:ring-1 focus:ring-[#10B981]"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-4 pt-1 border-t border-[#27272A]/60">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={includeFullPayloads}
                      onChange={(e) => setIncludeFullPayloads(e.target.checked)}
                      className="rounded bg-[#09090B] border-[#27272A] text-[#10B981] focus:ring-[#10B981]"
                    />
                    <span className="text-xs font-mono text-[#E4E4E7]">
                      Include raw payload strings in report (uncheck to redact raw text and retain SHA-256 digests only)
                    </span>
                  </label>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={handleCopyPublicKey}
                      className="px-2.5 py-1 rounded bg-[#09090B] hover:bg-[#27272A] text-[#A1A1AA] hover:text-[#FAFAFA] border border-[#27272A] text-xs font-mono flex items-center space-x-1.5 transition-colors"
                    >
                      <Key className="w-3.5 h-3.5 text-[#10B981]" />
                      <span>{copiedKey ? 'Copied Public Key' : 'Copy Public Key (PEM)'}</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Cryptographic Signature Guarantee Banner */}
              {signedDoc && (
                <div className="bg-[#18181B] border border-[#10B981]/40 rounded-lg p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <ShieldCheck className="w-5 h-5 text-[#10B981]" />
                      <span className="text-xs font-bold font-mono uppercase text-[#FAFAFA]">
                        Cryptographically Signed Audit Document
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-[#10B981] bg-[#10B981]/10 px-2 py-0.5 rounded border border-[#10B981]/30">
                      RFC 8785 Canonicalized
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono text-[#A1A1AA]">
                    <div className="truncate">
                      Key ID: <span className="text-[#FAFAFA]">{signedDoc.integrity_and_signature.key_id}</span>
                    </div>
                    <div className="truncate">
                      Signed At: <span className="text-[#FAFAFA]">{signedDoc.integrity_and_signature.signed_at}</span>
                    </div>
                    <div className="truncate md:col-span-2">
                      Payload SHA-256: <span className="text-[#10B981] font-mono">{signedDoc.integrity_and_signature.payload_digest_sha256}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Signed JSON Report Preview */}
              <div className="bg-[#18181B] border border-[#27272A] rounded-lg overflow-hidden space-y-0">
                <div className="p-3 bg-[#09090B] border-b border-[#27272A] flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <FileText className="w-4 h-4 text-[#10B981]" />
                    <span className="text-xs font-bold font-mono text-[#FAFAFA]">
                      {signedDoc?.report_header.report_id || 'AUDIT_REPORT'}.json
                    </span>
                    <span className="text-[10px] text-[#71717A] font-mono">
                      ({signedDoc?.inspection_session_logs.length || 0} inspection events)
                    </span>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={handleCopyJson}
                      disabled={!signedDoc}
                      className="px-3 py-1.5 rounded bg-[#18181B] hover:bg-[#27272A] text-[#FAFAFA] border border-[#27272A] text-xs font-mono flex items-center space-x-1.5 transition-colors"
                    >
                      {copiedJson ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-[#10B981]" />
                          <span className="text-[#10B981]">Copied JSON</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy JSON</span>
                        </>
                      )}
                    </button>

                    <button
                      onClick={handleDownloadJson}
                      disabled={!signedDoc}
                      className="px-3.5 py-1.5 rounded bg-[#10B981] hover:bg-[#059669] text-black font-bold text-xs font-mono flex items-center space-x-1.5 transition-all shadow-sm"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download Signed JSON</span>
                    </button>
                  </div>
                </div>

                <div className="p-4 bg-[#09090B] max-h-96 overflow-y-auto font-mono text-xs text-[#E4E4E7] leading-relaxed">
                  {isGenerating ? (
                    <div className="py-12 text-center text-[#71717A]">
                      <Sparkles className="w-6 h-6 mx-auto mb-2 text-[#10B981] animate-spin" />
                      <span>Canonicalizing and cryptographically signing session log...</span>
                    </div>
                  ) : signedDoc ? (
                    <pre className="whitespace-pre-wrap break-all text-[11px] selection:bg-[#10B981]/30">
                      {JSON.stringify(signedDoc, null, 2)}
                    </pre>
                  ) : (
                    <div className="py-12 text-center text-[#71717A]">
                      No audit report generated yet.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: SESSION LOGS TABLE */}
          {activeTab === 'logs' && (
            <div className="space-y-4">
              {/* Toolbar */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-[#18181B] p-3 rounded-lg border border-[#27272A]">
                <div className="relative w-full sm:w-80">
                  <Search className="w-3.5 h-3.5 text-[#71717A] absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Search payload, rule ID, tool..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-[#09090B] border border-[#27272A] rounded pl-8 pr-3 py-1.5 text-xs font-mono text-[#FAFAFA] placeholder-[#71717A] focus:border-[#10B981]"
                  />
                </div>

                <div className="flex items-center space-x-2 w-full sm:w-auto justify-between sm:justify-end">
                  <div className="flex rounded border border-[#27272A] bg-[#09090B] p-0.5 text-xs font-mono">
                    <button
                      onClick={() => setFilterAction('ALL')}
                      className={`px-2 py-1 rounded ${
                        filterAction === 'ALL'
                          ? 'bg-[#18181B] text-[#10B981] font-bold'
                          : 'text-[#71717A] hover:text-[#FAFAFA]'
                      }`}
                    >
                      All ({events.length})
                    </button>
                    <button
                      onClick={() => setFilterAction('BLOCK')}
                      className={`px-2 py-1 rounded ${
                        filterAction === 'BLOCK'
                          ? 'bg-[#18181B] text-[#F43F5E] font-bold'
                          : 'text-[#71717A] hover:text-[#FAFAFA]'
                      }`}
                    >
                      Blocked
                    </button>
                    <button
                      onClick={() => setFilterAction('SANITIZE')}
                      className={`px-2 py-1 rounded ${
                        filterAction === 'SANITIZE'
                          ? 'bg-[#18181B] text-[#F59E0B] font-bold'
                          : 'text-[#71717A] hover:text-[#FAFAFA]'
                      }`}
                    >
                      Sanitized
                    </button>
                  </div>

                  <button
                    onClick={handleClearLogs}
                    className="px-2.5 py-1.5 rounded bg-[#09090B] hover:bg-[#27272A] text-[#71717A] hover:text-[#F43F5E] border border-[#27272A] text-xs font-mono transition-colors"
                    title="Clear Session Logs"
                  >
                    Clear Logs
                  </button>
                </div>
              </div>

              {/* Events List */}
              {filteredEvents.length === 0 ? (
                <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-8 text-center font-mono">
                  <Terminal className="w-8 h-8 text-[#71717A] mx-auto mb-2" />
                  <p className="text-xs text-[#FAFAFA] font-bold">No inspection logs in current session buffer</p>
                  <p className="text-[11px] text-[#71717A] mt-1">
                    Inspecting payloads in the Live Inspector, running the Test Suite, or testing attack presets will automatically record here.
                  </p>
                </div>
              ) : (
                <div className="space-y-2">
                  {filteredEvents.map((evt) => {
                    const isExpanded = expandedEventId === evt.eventId;
                    return (
                      <div
                        key={evt.eventId}
                        className="bg-[#18181B] border border-[#27272A] rounded-lg overflow-hidden transition-colors"
                      >
                        <div
                          onClick={() => setExpandedEventId(isExpanded ? null : evt.eventId)}
                          className="p-3 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-[#27272A]/40"
                        >
                          <div className="flex items-center space-x-3">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold shrink-0 ${
                                evt.action === EnforcementAction.BLOCK
                                  ? 'bg-[#F43F5E]/20 text-[#F43F5E] border border-[#F43F5E]/40'
                                  : evt.action === EnforcementAction.SANITIZE_AND_WRAP
                                  ? 'bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/40'
                                  : 'bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40'
                              }`}
                            >
                              {evt.action}
                            </span>

                            <div className="truncate">
                              <span className="text-xs font-mono text-[#FAFAFA] font-semibold">
                                {evt.rawPayload.slice(0, 50)}...
                              </span>
                              <div className="text-[10px] text-[#71717A] font-mono flex items-center space-x-2 mt-0.5">
                                <span>{evt.timestamp.slice(11, 19)}</span>
                                <span>•</span>
                                <span>Origin: {evt.trustLevelLabel}</span>
                                {evt.targetToolName && (
                                  <>
                                    <span>•</span>
                                    <span>Target: {evt.targetToolName}</span>
                                  </>
                                )}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center space-x-3 shrink-0 self-end sm:self-center">
                            <div className="text-right font-mono text-xs">
                              <span className="text-[#71717A] text-[10px]">RISK: </span>
                              <span className="font-bold text-[#FAFAFA]">
                                {evt.maxRiskScore.toFixed(2)}
                              </span>
                            </div>

                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#09090B] text-[#71717A] border border-[#27272A]">
                              {evt.violationsCount} viols
                            </span>

                            <span className="text-xs font-mono text-[#10B981]">
                              {evt.processingTimeMs}ms
                            </span>
                          </div>
                        </div>

                        {/* Expanded inspection details */}
                        {isExpanded && (
                          <div className="p-4 bg-[#09090B] border-t border-[#27272A] font-mono text-xs space-y-3">
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] text-[#A1A1AA]">
                              <div>
                                <span className="text-[#71717A]">Event ID: </span>
                                <span className="text-[#FAFAFA]">{evt.eventId}</span>
                              </div>
                              <div>
                                <span className="text-[#71717A]">Payload SHA-256: </span>
                                <span className="text-[#10B981] break-all">{evt.rawPayloadSha256}</span>
                              </div>
                              <div>
                                <span className="text-[#71717A]">Boundary Container: </span>
                                <span className="text-[#10B981]">{evt.taintAnalysis.boundaryToken}</span>
                              </div>
                              <div>
                                <span className="text-[#71717A]">Taint Status: </span>
                                <span className={evt.taintAnalysis.isTainted ? 'text-[#F43F5E] font-bold' : 'text-[#10B981]'}>
                                  {evt.taintAnalysis.isTainted ? 'TAINTED EXTERNAL' : 'UNTAINTED'}
                                </span>
                              </div>
                            </div>

                            <div>
                              <div className="text-[10px] uppercase font-bold text-[#71717A] mb-1">
                                Full Payload:
                              </div>
                              <pre className="bg-[#18181B] p-2.5 rounded border border-[#27272A] text-[#FAFAFA] whitespace-pre-wrap break-all text-[11px]">
                                {evt.rawPayload}
                              </pre>
                            </div>

                            {evt.violations.length > 0 && (
                              <div>
                                <div className="text-[10px] uppercase font-bold text-[#71717A] mb-1">
                                  Detected Threat Violations:
                                </div>
                                <div className="space-y-1.5">
                                  {evt.violations.map((v, i) => (
                                    <div
                                      key={i}
                                      className="p-2 bg-[#18181B] rounded border border-[#27272A] flex items-center justify-between text-xs"
                                    >
                                      <div>
                                        <span className="text-[#F43F5E] font-bold">[{v.rule_id}]</span>{' '}
                                        <span className="text-[#FAFAFA]">{v.description}</span>
                                      </div>
                                      <span className="text-[#F43F5E] font-bold">
                                        Risk: {v.risk_score.toFixed(2)}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {onSelectEventForInspector && (
                              <div className="pt-2 flex justify-end">
                                <button
                                  onClick={() => {
                                    onSelectEventForInspector(
                                      evt.rawPayload,
                                      evt.trustLevel,
                                      evt.targetToolId
                                    );
                                    onClose();
                                  }}
                                  className="px-3 py-1.5 rounded bg-[#18181B] hover:bg-[#27272A] text-[#10B981] border border-[#10B981]/40 text-xs font-mono flex items-center space-x-1.5 transition-colors"
                                >
                                  <Terminal className="w-3.5 h-3.5" />
                                  <span>Replay In Live Inspector</span>
                                </button>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: VERIFY SIGNATURE */}
          {activeTab === 'verify' && (
            <div className="space-y-6">
              <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-[#A1A1AA] flex items-center space-x-2">
                    <Fingerprint className="w-4 h-4 text-[#10B981]" />
                    <span>Cryptographic Audit Report Verifier</span>
                  </h3>
                  <button
                    onClick={handleLoadCurrentIntoVerifier}
                    className="text-xs text-[#10B981] hover:underline font-mono"
                  >
                    Paste Current Active Report
                  </button>
                </div>
                <p className="text-xs text-[#71717A] font-mono leading-relaxed">
                  Paste any PromptGuard JSON audit report to cryptographically verify its ECDSA P-256 digital signature, RFC 8785 canonical hash, and data integrity.
                </p>

                <textarea
                  value={verifyInputJson}
                  onChange={(e) => setVerifyInputJson(e.target.value)}
                  rows={8}
                  placeholder="Paste JSON audit report content here..."
                  className="w-full bg-[#09090B] border border-[#27272A] focus:border-[#10B981] rounded p-3 text-xs font-mono text-[#FAFAFA] placeholder-[#71717A] resize-y"
                />

                <div className="flex justify-end">
                  <button
                    onClick={handleVerifyPastedJson}
                    disabled={isVerifying || !verifyInputJson.trim()}
                    className="px-4 py-2 rounded bg-[#10B981] hover:bg-[#059669] text-black font-bold text-xs font-mono flex items-center space-x-2 transition-all disabled:opacity-50"
                  >
                    <ShieldCheck className="w-4 h-4" />
                    <span>{isVerifying ? 'Verifying...' : 'Verify Cryptographic Signature'}</span>
                  </button>
                </div>
              </div>

              {/* Verification Outcome Box */}
              {verificationResult && (
                <div
                  className={`rounded-lg p-5 border space-y-3 font-mono text-xs ${
                    verificationResult.isValid
                      ? 'bg-[#18181B] border-[#10B981]'
                      : 'bg-[#18181B] border-[#F43F5E]'
                  }`}
                >
                  <div className="flex items-center justify-between border-b border-[#27272A] pb-3">
                    <div className="flex items-center space-x-2">
                      {verificationResult.isValid ? (
                        <CheckCircle2 className="w-6 h-6 text-[#10B981]" />
                      ) : (
                        <XCircle className="w-6 h-6 text-[#F43F5E]" />
                      )}
                      <div>
                        <div
                          className={`text-sm font-bold uppercase ${
                            verificationResult.isValid ? 'text-[#10B981]' : 'text-[#F43F5E]'
                          }`}
                        >
                          {verificationResult.isValid
                            ? 'SIGNATURE VALID — ZERO TAMPERING DETECTED'
                            : 'SIGNATURE VERIFICATION FAILED'}
                        </div>
                        <div className="text-[11px] text-[#71717A] mt-0.5">
                          {verificationResult.isValid
                            ? 'The report payload is authentic, bit-level identical to the signed snapshot, and issued by the reported key.'
                            : verificationResult.error || 'The cryptographic signature did not match.'}
                        </div>
                      </div>
                    </div>

                    <span
                      className={`text-[10px] px-2 py-1 rounded font-bold border ${
                        verificationResult.isValid
                          ? 'bg-[#10B981]/20 text-[#10B981] border-[#10B981]/40'
                          : 'bg-[#F43F5E]/20 text-[#F43F5E] border-[#F43F5E]/40'
                      }`}
                    >
                      {verificationResult.isValid ? 'VERIFIED AUTHENTIC' : 'UNTRUSTED / TAMPERED'}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-[#A1A1AA]">
                    <div>
                      Algorithm: <span className="text-[#FAFAFA]">{verificationResult.algorithm}</span>
                    </div>
                    <div>
                      Signer Key ID: <span className="text-[#FAFAFA]">{verificationResult.keyId}</span>
                    </div>
                    <div>
                      Timestamp: <span className="text-[#FAFAFA]">{verificationResult.signedAt || 'N/A'}</span>
                    </div>
                    <div>
                      Digest Match: <span className={verificationResult.digestMatch ? 'text-[#10B981] font-bold' : 'text-[#F43F5E] font-bold'}>
                        {verificationResult.digestMatch ? 'MATCH (SHA-256 Valid)' : 'MISMATCH'}
                      </span>
                    </div>
                    <div className="md:col-span-2 truncate">
                      Computed Digest: <span className="text-[#FAFAFA] font-mono">{verificationResult.computedDigestSha256 || 'N/A'}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 sm:p-4 border-t border-[#27272A] bg-[#09090B] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-[#71717A]">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
            <span>SPEC: RFC-8785 JSON Canonicalization + ECDSA-P256-SHA256</span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded bg-[#18181B] hover:bg-[#27272A] text-[#FAFAFA] border border-[#27272A] text-xs font-mono transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
