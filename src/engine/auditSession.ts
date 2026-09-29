/**
 * PromptGuard Enterprise Kernel - Inspection Session & Taint Audit Engine
 * 
 * Tracks real-time inspection events, aggregates taint provenance metrics,
 * and compiles cryptographically verifiable audit reports.
 */

import {
  EnforcementAction,
  EngineConfig,
  SecurityViolation,
  TaintContainer,
  ThreatCategory,
  ToolDefinition,
  TrustLevel,
} from '../types';
import { AVAILABLE_TOOLS, DEFAULT_ENGINE_CONFIG } from './taintEngine';
import {
  computeSha256Hex,
  getOrCreateSessionKeyPair,
  signAuditReport,
  SignatureBlock,
} from './cryptoSigner';

export interface AuditInspectionEvent {
  eventId: string;
  timestamp: string;
  sourceOrigin: 'live_inspector' | 'test_suite' | 'payload_fuzzer' | 'taint_graph' | 'api_gateway';
  trustLevel: TrustLevel;
  trustLevelLabel: string;
  targetToolId?: string;
  targetToolName?: string;
  targetToolPrivilege?: string;
  rawPayload: string;
  rawPayloadSha256: string;
  action: EnforcementAction;
  maxRiskScore: number;
  processingTimeMs: number;
  violationsCount: number;
  violations: SecurityViolation[];
  taintAnalysis: {
    boundaryToken: string;
    isTainted: boolean;
    hadZeroWidth: boolean;
    zeroWidthCount: number;
    hadHomoglyphs: boolean;
    homoglyphCount: number;
    decodedLayersCount: number;
    astNodesCount: number;
    dangerousAstNodesCount: number;
    isPrivilegeEscalationAttempt: boolean;
    taintPolicyViolation: boolean;
    cleanNormalizedPreview: string;
    wrappedEnvelope: string;
  };
}

export interface SessionMetrics {
  sessionId: string;
  sessionStartTime: string;
  totalInspections: number;
  allowedCount: number;
  sanitizedCount: number;
  blockedCount: number;
  taintViolationsCount: number;
  threatDistribution: Record<ThreatCategory, number>;
  averageLatencyMs: number;
  activeKeyId?: string;
}

export interface ExportReportOptions {
  includeFullPayloads?: boolean; // if false, redacts raw text to [REDACTED_FOR_PRIVACY] but keeps SHA256
  auditorNotes?: string;
  organizationName?: string;
  systemEnvironment?: string;
}

export interface SignedAuditReportDocument {
  $schema: string;
  report_header: {
    report_id: string;
    generated_at: string;
    kernel_version: string;
    organization: string;
    environment: string;
    auditor_notes?: string;
    deterministic_guarantee: string;
  };
  session_summary: {
    session_id: string;
    session_start_time: string;
    total_inspections: number;
    enforcement_summary: {
      allowed: number;
      sanitized_and_wrapped: number;
      blocked: number;
      taint_policy_violations: number;
    };
    threat_category_breakdown: Record<string, number>;
    average_latency_ms: number;
    engine_configuration_snapshot: EngineConfig;
  };
  taint_provenance_results: {
    total_tainted_ingress_events: number;
    trusted_system_events: number;
    authenticated_user_events: number;
    privileged_tools_dispatched: {
      read_only: number;
      elevated_write: number;
      destructive_admin: number;
      external_network: number;
    };
    step_up_authorizations_required: number;
    boundary_tokens_minted: string[];
  };
  inspection_session_logs: Array<{
    event_id: string;
    timestamp: string;
    source: string;
    trust_level: {
      numeric: number;
      label: string;
    };
    target_tool?: {
      id: string;
      name: string;
      privilege: string;
    };
    payload_hash_sha256: string;
    payload_content: string;
    enforcement_action: EnforcementAction;
    risk_score: number;
    latency_ms: number;
    violations_detected: SecurityViolation[];
    taint_provenance: {
      boundary_token: string;
      data_is_tainted: boolean;
      decloaking_applied: {
        zero_width_stripped: boolean;
        homoglyphs_normalized: boolean;
        recursive_layers_unpacked: number;
      };
      ast_code_audit: {
        nodes_evaluated: number;
        dangerous_calls_blocked: number;
      };
      taint_barrier_enforced: boolean;
    };
  }>;
  integrity_and_signature: SignatureBlock;
}

const SESSION_STORAGE_KEY = 'promptguard_audit_session_logs_v1';
const SESSION_ID_KEY = 'promptguard_audit_session_id';

class AuditSessionManager {
  private sessionId: string;
  private sessionStartTime: string;
  private events: AuditInspectionEvent[] = [];
  private listeners: Set<() => void> = new Set();

  constructor() {
    // Generate or restore session ID
    let storedSessionId = sessionStorage.getItem(SESSION_ID_KEY);
    if (!storedSessionId) {
      const randHex = Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) =>
        b.toString(16).padStart(2, '0')
      ).join('');
      storedSessionId = `SESS-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${randHex.toUpperCase()}`;
      sessionStorage.setItem(SESSION_ID_KEY, storedSessionId);
    }
    this.sessionId = storedSessionId;
    this.sessionStartTime = new Date().toISOString();

    // Restore existing events if available
    try {
      const stored = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (stored) {
        this.events = JSON.parse(stored);
      }
    } catch {
      this.events = [];
    }
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify() {
    try {
      sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(this.events.slice(-100)));
    } catch {
      // Ignore quota errors
    }
    this.listeners.forEach((fn) => fn());
  }

  /**
   * Log an inspection result and its taint analysis outcome
   */
  public async logInspection(
    taintResult: TaintContainer,
    sourceOrigin: AuditInspectionEvent['sourceOrigin'] = 'live_inspector',
    targetToolId?: string
  ): Promise<AuditInspectionEvent> {
    const rawPayloadSha256 = await computeSha256Hex(taintResult.original_text);

    const randId = Array.from(crypto.getRandomValues(new Uint8Array(3)), (b) =>
      b.toString(16).padStart(2, '0')
    ).join('').toUpperCase();
    const eventId = `EVT-${Date.now().toString(36).toUpperCase()}-${randId}`;

    const targetTool = targetToolId
      ? AVAILABLE_TOOLS.find((t) => t.id === targetToolId)
      : undefined;

    const dangerousAstNodes =
      taintResult.layersInfo.astNodes.filter((n) => n.isDangerous) || [];

    const isPrivilegeEscalationAttempt =
      taintResult.trust_level === TrustLevel.UNTRUSTED_EXTERNAL &&
      targetTool != null &&
      targetTool.privilege !== 'READ_ONLY';

    const taintPolicyViolation = taintResult.violations.some(
      (v) => v.category === ThreatCategory.TAINT_POLICY_VIOLATION
    );

    const event: AuditInspectionEvent = {
      eventId,
      timestamp: new Date().toISOString(),
      sourceOrigin,
      trustLevel: taintResult.trust_level,
      trustLevelLabel: TrustLevel[taintResult.trust_level],
      targetToolId: targetTool?.id,
      targetToolName: targetTool?.name,
      targetToolPrivilege: targetTool?.privilege,
      rawPayload: taintResult.original_text,
      rawPayloadSha256,
      action: taintResult.action,
      maxRiskScore: taintResult.max_risk,
      processingTimeMs: taintResult.processingTimeMs,
      violationsCount: taintResult.violations.length,
      violations: taintResult.violations,
      taintAnalysis: {
        boundaryToken: taintResult.boundary_token,
        isTainted: taintResult.trust_level === TrustLevel.UNTRUSTED_EXTERNAL,
        hadZeroWidth: taintResult.layersInfo.hadZeroWidth,
        zeroWidthCount: taintResult.layersInfo.zeroWidthMatches?.length || 0,
        hadHomoglyphs: taintResult.layersInfo.hadHomoglyphs,
        homoglyphCount: taintResult.layersInfo.homoglyphMatches?.length || 0,
        decodedLayersCount: taintResult.layersInfo.decodedLayers?.length || 0,
        astNodesCount: taintResult.layersInfo.astNodes?.length || 0,
        dangerousAstNodesCount: dangerousAstNodes.length,
        isPrivilegeEscalationAttempt,
        taintPolicyViolation,
        cleanNormalizedPreview: taintResult.layersInfo.cleanNormalized?.slice(0, 120) || '',
        wrappedEnvelope: taintResult.normalized_text,
      },
    };

    // Prepend new event to log
    this.events.unshift(event);
    if (this.events.length > 250) {
      this.events = this.events.slice(0, 250);
    }

    this.notify();
    return event;
  }

  public getEvents(): AuditInspectionEvent[] {
    return [...this.events];
  }

  public getSessionId(): string {
    return this.sessionId;
  }

  public getSessionStartTime(): string {
    return this.sessionStartTime;
  }

  public clearLogs() {
    this.events = [];
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
    this.notify();
  }

  public getMetrics(): SessionMetrics {
    const total = this.events.length;
    let allowed = 0;
    let sanitized = 0;
    let blocked = 0;
    let taintViolations = 0;
    let totalLatency = 0;

    const threatDistribution: Record<ThreatCategory, number> = {
      [ThreatCategory.HOMOGLYPH_OBFUSCATION]: 0,
      [ThreatCategory.INDIRECT_ROLE_HIJACK]: 0,
      [ThreatCategory.SPECIAL_TOKEN_INJECTION]: 0,
      [ThreatCategory.MARKDOWN_EXFILTRATION]: 0,
      [ThreatCategory.RECURSIVE_ENCODING_BYPASS]: 0,
      [ThreatCategory.UNSAFE_CODE_EXECUTION]: 0,
      [ThreatCategory.TAINT_POLICY_VIOLATION]: 0,
      [ThreatCategory.ZERO_WIDTH_SMUGGLING]: 0,
    };

    for (const evt of this.events) {
      if (evt.action === EnforcementAction.BLOCK) blocked++;
      else if (evt.action === EnforcementAction.SANITIZE_AND_WRAP) sanitized++;
      else allowed++;

      if (evt.taintAnalysis.taintPolicyViolation) {
        taintViolations++;
      }

      totalLatency += evt.processingTimeMs;

      for (const v of evt.violations) {
        if (threatDistribution[v.category] !== undefined) {
          threatDistribution[v.category]++;
        }
      }
    }

    return {
      sessionId: this.sessionId,
      sessionStartTime: this.sessionStartTime,
      totalInspections: total,
      allowedCount: allowed,
      sanitizedCount: sanitized,
      blockedCount: blocked,
      taintViolationsCount: taintViolations,
      threatDistribution,
      averageLatencyMs: total > 0 ? Number((totalLatency / total).toFixed(3)) : 0,
    };
  }

  /**
   * Generates, canonicalizes, and cryptographically signs the complete JSON audit report
   */
  public async generateSignedAuditReport(
    engineConfig: EngineConfig = DEFAULT_ENGINE_CONFIG,
    options: ExportReportOptions = {}
  ): Promise<{ signedReport: SignedAuditReportDocument; signatureBlock: SignatureBlock }> {
    const keyPair = await getOrCreateSessionKeyPair();
    const metrics = this.getMetrics();
    const generatedAt = new Date().toISOString();

    const reportId = `AUDIT-${generatedAt.slice(0, 10).replace(/-/g, '')}-${metrics.sessionId.slice(-6)}`;

    // Calculate detailed taint provenance summary
    const boundaryTokensMinted = Array.from(
      new Set(this.events.map((e) => e.taintAnalysis.boundaryToken).filter(Boolean))
    );

    const privilegedDispatches = {
      read_only: 0,
      elevated_write: 0,
      destructive_admin: 0,
      external_network: 0,
    };

    let untrustedIngress = 0;
    let systemIngress = 0;
    let authUserIngress = 0;
    let stepUpRequired = 0;

    for (const evt of this.events) {
      if (evt.trustLevel === TrustLevel.UNTRUSTED_EXTERNAL) untrustedIngress++;
      else if (evt.trustLevel === TrustLevel.TRUSTED_SYSTEM) systemIngress++;
      else if (evt.trustLevel === TrustLevel.AUTHENTICATED_USER) authUserIngress++;

      if (evt.targetToolPrivilege === 'READ_ONLY') privilegedDispatches.read_only++;
      else if (evt.targetToolPrivilege === 'ELEVATED_WRITE') privilegedDispatches.elevated_write++;
      else if (evt.targetToolPrivilege === 'DESTRUCTIVE_ADMIN') privilegedDispatches.destructive_admin++;
      else if (evt.targetToolPrivilege === 'EXTERNAL_NETWORK') privilegedDispatches.external_network++;

      if (evt.taintAnalysis.isPrivilegeEscalationAttempt) {
        stepUpRequired++;
      }
    }

    // Prepare log items with option for payload privacy redaction
    const includePayloads = options.includeFullPayloads !== false;

    const formattedLogs = this.events.map((evt) => ({
      event_id: evt.eventId,
      timestamp: evt.timestamp,
      source: evt.sourceOrigin,
      trust_level: {
        numeric: evt.trustLevel,
        label: evt.trustLevelLabel,
      },
      target_tool: evt.targetToolId
        ? {
            id: evt.targetToolId,
            name: evt.targetToolName || '',
            privilege: evt.targetToolPrivilege || 'UNKNOWN',
          }
        : undefined,
      payload_hash_sha256: evt.rawPayloadSha256,
      payload_content: includePayloads ? evt.rawPayload : `[REDACTED_CONFIDENTIAL_HASH:${evt.rawPayloadSha256.slice(0, 16)}]`,
      enforcement_action: evt.action,
      risk_score: evt.maxRiskScore,
      latency_ms: evt.processingTimeMs,
      violations_detected: evt.violations,
      taint_provenance: {
        boundary_token: evt.taintAnalysis.boundaryToken,
        data_is_tainted: evt.taintAnalysis.isTainted,
        decloaking_applied: {
          zero_width_stripped: evt.taintAnalysis.hadZeroWidth,
          homoglyphs_normalized: evt.taintAnalysis.hadHomoglyphs,
          recursive_layers_unpacked: evt.taintAnalysis.decodedLayersCount,
        },
        ast_code_audit: {
          nodes_evaluated: evt.taintAnalysis.astNodesCount,
          dangerous_calls_blocked: evt.taintAnalysis.dangerousAstNodesCount,
        },
        taint_barrier_enforced: evt.taintAnalysis.taintPolicyViolation,
      },
    }));

    // Construct unsigned report payload (all keys will be canonically sorted during signing)
    const reportDataWithoutSignature = {
      $schema: 'https://promptguard.enterprise/schemas/v1/audit-report.json',
      report_header: {
        report_id: reportId,
        generated_at: generatedAt,
        kernel_version: 'PromptGuard Enterprise Kernel v4.2.1',
        organization: options.organizationName || 'Enterprise Security Operations Center (SecOps)',
        environment: options.systemEnvironment || 'Production Firewall Ingress',
        auditor_notes: options.auditorNotes || 'Deterministic AI Firewall & Taint-Tracking Audit Verification Log',
        deterministic_guarantee: 'ZERO_AI_OVERHEAD_REPRODUCIBLE_RULES',
      },
      session_summary: {
        session_id: this.sessionId,
        session_start_time: this.sessionStartTime,
        total_inspections: metrics.totalInspections,
        enforcement_summary: {
          allowed: metrics.allowedCount,
          sanitized_and_wrapped: metrics.sanitizedCount,
          blocked: metrics.blockedCount,
          taint_policy_violations: metrics.taintViolationsCount,
        },
        threat_category_breakdown: metrics.threatDistribution,
        average_latency_ms: metrics.averageLatencyMs,
        engine_configuration_snapshot: engineConfig,
      },
      taint_provenance_results: {
        total_tainted_ingress_events: untrustedIngress,
        trusted_system_events: systemIngress,
        authenticated_user_events: authUserIngress,
        privileged_tools_dispatched: privilegedDispatches,
        step_up_authorizations_required: stepUpRequired,
        boundary_tokens_minted: boundaryTokensMinted,
      },
      inspection_session_logs: formattedLogs,
    };

    const { signedReport, signatureBlock } = await signAuditReport(reportDataWithoutSignature, keyPair);

    return {
      signedReport: signedReport as SignedAuditReportDocument,
      signatureBlock,
    };
  }
}

// Global Singleton instance
export const auditSession = new AuditSessionManager();
