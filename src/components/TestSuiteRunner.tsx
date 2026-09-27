import React, { useState, useEffect } from 'react';
import {
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Zap,
  Shield,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
  Terminal,
  Filter,
} from 'lucide-react';
import { INITIAL_TEST_VECTORS } from '../data/testVectors';
import { PromptGuardEngine } from '../engine/taintEngine';
import { EnforcementAction, TestResult, TestVector } from '../types';

interface TestSuiteRunnerProps {
  engine: PromptGuardEngine;
}

export const TestSuiteRunner: React.FC<TestSuiteRunnerProps> = ({ engine }) => {
  const [testVectors, setTestVectors] = useState<TestVector[]>(INITIAL_TEST_VECTORS);
  const [results, setResults] = useState<TestResult[]>([]);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [expandedTestId, setExpandedTestId] = useState<string | null>(null);
  const [selectedFilter, setSelectedFilter] = useState<'ALL' | 'PASSED' | 'FAILED'>('ALL');

  // Run all tests
  const runTests = () => {
    setIsRunning(true);
    const newResults: TestResult[] = [];

    for (const test of testVectors) {
      const t0 = performance.now();
      const taintContainer = engine.inspectAndContain(test.payload, test.trust, test.targetTool);
      const t1 = performance.now();

      const isBlocked = taintContainer.action === EnforcementAction.BLOCK;
      const passed = isBlocked === test.expect_block;

      newResults.push({
        test,
        result: taintContainer,
        passed,
        durationMs: Number((t1 - t0).toFixed(3)),
      });
    }

    setResults(newResults);
    setIsRunning(false);
  };

  // Run automatically on first render
  useEffect(() => {
    runTests();
  }, []);

  const totalTests = results.length;
  const passedTests = results.filter((r) => r.passed).length;
  const failedTests = results.filter((r) => !r.passed).length;
  const passRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(1) : '0.0';
  const avgLatency =
    totalTests > 0
      ? (results.reduce((acc, r) => acc + r.durationMs, 0) / totalTests).toFixed(3)
      : '0.000';

  const filteredResults = results.filter((r) => {
    if (selectedFilter === 'PASSED') return r.passed;
    if (selectedFilter === 'FAILED') return !r.passed;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Test Suite Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Pass Rate Card */}
        <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 shadow-sm">
          <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-widest text-[#71717A] font-mono">
            <span>SUITE PASS RATE</span>
            <CheckCircle2 className="w-4 h-4 text-[#10B981]" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-[#10B981]">{passRate}%</span>
            <span className="text-xs text-[#71717A] font-mono">
              ({passedTests}/{totalTests} passed)
            </span>
          </div>
          <div className="w-full h-1.5 bg-[#27272A] rounded-full mt-3 overflow-hidden">
            <div
              className="h-full bg-[#10B981] transition-all duration-500"
              style={{ width: `${passRate}%` }}
            />
          </div>
        </div>

        {/* Total Attack Vectors */}
        <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 shadow-sm">
          <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-widest text-[#71717A] font-mono">
            <span>TOTAL ATTACK VECTORS</span>
            <Shield className="w-4 h-4 text-[#10B981]" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-[#FAFAFA]">{totalTests}</span>
            <span className="text-xs text-[#71717A] font-mono">Vectors Evaluated</span>
          </div>
          <p className="text-[11px] text-[#71717A] mt-2 font-mono">
            Homoglyph, Base64, ChatML, AST, Exfil
          </p>
        </div>

        {/* Average Processing Latency */}
        <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 shadow-sm">
          <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-widest text-[#71717A] font-mono">
            <span>AVERAGE LATENCY</span>
            <Clock className="w-4 h-4 text-[#3B82F6]" />
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-3xl font-black font-mono text-[#3B82F6]">{avgLatency}</span>
            <span className="text-xs text-[#71717A] font-mono">ms / inspection</span>
          </div>
          <p className="text-[11px] text-[#71717A] mt-2 font-mono">
            Deterministic zero-AI overhead
          </p>
        </div>

        {/* Execution Control */}
        <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-widest text-[#71717A] font-mono">
            <span>RUNNER ACTIONS</span>
            <Zap className="w-4 h-4 text-[#F59E0B]" />
          </div>
          <div className="mt-2 flex items-center space-x-2">
            <button
              id="btn-run-all-tests"
              onClick={runTests}
              disabled={isRunning}
              className="flex-1 bg-[#10B981] hover:bg-[#059669] text-black text-xs font-mono font-bold py-2.5 px-3 rounded shadow-sm flex items-center justify-center space-x-1.5 transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isRunning ? 'Running...' : 'Run Test Suite'}</span>
            </button>
            <button
              onClick={runTests}
              className="p-2.5 rounded border border-[#27272A] bg-[#09090B] text-[#71717A] hover:text-[#FAFAFA] hover:bg-[#27272A] transition-colors"
              title="Reset and Rerun"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Test Vectors Detailed Table */}
      <div className="bg-[#18181B] border border-[#27272A] rounded-lg overflow-hidden shadow-sm">
        {/* Header and Filter Toolbar */}
        <div className="p-4 border-b border-[#27272A] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-bold text-[#A1A1AA] uppercase tracking-widest font-mono flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-[#10B981]" />
              <span>SECURITY EVALUATION SUITE</span>
            </h3>
            <p className="text-xs text-[#71717A] mt-0.5 font-mono">
              Deterministic verification against prompt injection, evasion, and taint escalation vectors
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <div className="flex rounded border border-[#27272A] bg-[#09090B] p-0.5 text-xs font-mono">
              <button
                onClick={() => setSelectedFilter('ALL')}
                className={`px-2.5 py-1 rounded transition-all ${
                  selectedFilter === 'ALL' ? 'bg-[#18181B] text-[#10B981] font-bold' : 'text-[#71717A] hover:text-[#FAFAFA]'
                }`}
              >
                All ({results.length})
              </button>
              <button
                onClick={() => setSelectedFilter('PASSED')}
                className={`px-2.5 py-1 rounded transition-all ${
                  selectedFilter === 'PASSED' ? 'bg-[#18181B] text-[#10B981] font-bold' : 'text-[#71717A] hover:text-[#FAFAFA]'
                }`}
              >
                Passed ({passedTests})
              </button>
              <button
                onClick={() => setSelectedFilter('FAILED')}
                className={`px-2.5 py-1 rounded transition-all ${
                  selectedFilter === 'FAILED' ? 'bg-[#18181B] text-[#F43F5E] font-bold' : 'text-[#71717A] hover:text-[#FAFAFA]'
                }`}
              >
                Failed ({failedTests})
              </button>
            </div>
          </div>
        </div>

        {/* Results List */}
        <div className="divide-y divide-[#27272A]">
          {filteredResults.map((item) => {
            const isExpanded = expandedTestId === item.test.id;
            return (
              <div key={item.test.id} className="transition-colors hover:bg-[#27272A]/30">
                <div
                  onClick={() => setExpandedTestId(isExpanded ? null : item.test.id)}
                  className="p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="flex items-start space-x-3">
                    <div className="mt-0.5">
                      {item.passed ? (
                        <CheckCircle2 className="w-5 h-5 text-[#10B981] shrink-0" />
                      ) : (
                        <XCircle className="w-5 h-5 text-[#F43F5E] shrink-0" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs font-bold text-[#FAFAFA]">
                          {item.test.name}
                        </span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-[#09090B] text-[#71717A] font-mono border border-[#27272A]">
                          {item.test.category}
                        </span>
                      </div>
                      <p className="text-xs text-[#71717A] mt-1 font-sans">
                        {item.test.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-4 self-end sm:self-center shrink-0">
                    <div className="text-right font-mono text-xs">
                      <div className="text-[#71717A] text-[10px]">RISK SCORE</div>
                      <div className="font-bold text-[#E4E4E7]">
                        {item.result.max_risk.toFixed(2)}
                      </div>
                    </div>

                    <div className="text-right font-mono text-xs">
                      <div className="text-[#71717A] text-[10px]">ACTION</div>
                      <span
                        className={`text-[11px] px-2 py-0.5 rounded font-bold font-mono ${
                          item.result.action === EnforcementAction.BLOCK
                            ? 'bg-[#F43F5E]/20 text-[#F43F5E] border border-[#F43F5E]/40'
                            : item.result.action === EnforcementAction.SANITIZE_AND_WRAP
                            ? 'bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/40'
                            : 'bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40'
                        }`}
                      >
                        {item.result.action}
                      </span>
                    </div>

                    <div className="text-right font-mono text-xs hidden md:block">
                      <div className="text-[#71717A] text-[10px]">LATENCY</div>
                      <div className="text-[#71717A]">{item.durationMs} ms</div>
                    </div>

                    <div className="text-[#71717A]">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>
                </div>

                {/* Expanded Inspection Breakdown */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-2 bg-[#09090B] border-t border-[#27272A] space-y-3 font-mono text-xs">
                    <div>
                      <div className="text-[#71717A] text-[11px] font-bold uppercase tracking-wider mb-1">Payload Sent:</div>
                      <div className="bg-[#18181B] p-2.5 rounded border border-[#27272A] text-[#FAFAFA] break-all">
                        {item.test.payload}
                      </div>
                    </div>

                    {item.result.violations.length > 0 && (
                      <div>
                        <div className="text-[#71717A] text-[11px] font-bold uppercase tracking-wider mb-1">
                          Violations Detected ({item.result.violations.length}):
                        </div>
                        <div className="space-y-1.5">
                          {item.result.violations.map((v, vIdx) => (
                            <div
                              key={vIdx}
                              className="bg-[#18181B] p-2 rounded border border-[#27272A] flex items-start justify-between gap-2"
                            >
                              <div>
                                <span className="text-[#F43F5E] font-bold">[{v.rule_id}]</span>{' '}
                                <span className="text-[#E4E4E7] font-sans text-xs">{v.description}</span>
                                <div className="text-[11px] text-[#71717A] mt-0.5">
                                  Sample: <span className="text-[#F43F5E] font-bold">{v.extracted_sample}</span>
                                </div>
                              </div>
                              <span className="text-[#F43F5E] font-bold shrink-0">
                                Risk: {v.risk_score.toFixed(2)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div>
                      <div className="text-[#71717A] text-[11px] font-bold uppercase tracking-wider mb-1">
                        Encapsulated Boundary Output:
                      </div>
                      <pre className="bg-[#18181B] p-2.5 rounded border border-[#27272A] text-[#FAFAFA] whitespace-pre-wrap break-all text-[11px]">
                        {item.result.normalized_text}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
