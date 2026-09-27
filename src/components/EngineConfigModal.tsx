import React, { useState } from 'react';
import {
  X,
  Sliders,
  RotateCcw,
  Check,
  Shield,
  Layers,
} from 'lucide-react';
import { DEFAULT_ENGINE_CONFIG, PromptGuardEngine } from '../engine/taintEngine';
import { EngineConfig } from '../types';

interface EngineConfigModalProps {
  engine: PromptGuardEngine;
  isOpen: boolean;
  onClose: () => void;
  onConfigChanged: () => void;
}

export const EngineConfigModal: React.FC<EngineConfigModalProps> = ({
  engine,
  isOpen,
  onClose,
  onConfigChanged,
}) => {
  const [config, setConfig] = useState<EngineConfig>(engine.getConfig());

  if (!isOpen) return null;

  const handleSave = () => {
    engine.updateConfig(config);
    onConfigChanged();
    onClose();
  };

  const handleReset = () => {
    setConfig({ ...DEFAULT_ENGINE_CONFIG });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#18181B] border border-[#27272A] rounded-lg max-w-lg w-full p-6 shadow-2xl space-y-5">
        <div className="flex items-center justify-between border-b border-[#27272A] pb-3">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded bg-[#09090B] border border-[#27272A] flex items-center justify-center">
              <Sliders className="w-4 h-4 text-[#10B981]" />
            </div>
            <div>
              <h3 className="text-xs font-bold text-[#A1A1AA] uppercase tracking-widest font-mono">FIREWALL ENGINE POLICIES</h3>
              <p className="text-xs text-[#71717A] font-mono">Configure sensitivity thresholds and active defense layers</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-[#71717A] hover:text-[#FAFAFA] hover:bg-[#27272A] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4 max-h-[420px] overflow-y-auto pr-1">
          {/* Thresholds */}
          <div className="space-y-3 bg-[#09090B] p-3.5 rounded border border-[#27272A]">
            <div className="flex items-center justify-between text-xs font-semibold text-[#FAFAFA] font-mono">
              <span>Block Risk Threshold</span>
              <span className="text-[#10B981] font-bold">
                {config.blockRiskThreshold.toFixed(2)}
              </span>
            </div>
            <input
              type="range"
              min="0.5"
              max="1.0"
              step="0.05"
              value={config.blockRiskThreshold}
              onChange={(e) => setConfig({ ...config, blockRiskThreshold: parseFloat(e.target.value) })}
              className="w-full accent-[#10B981] cursor-pointer"
            />
            <p className="text-[11px] text-[#71717A] font-mono">
              Payloads with max risk score equal or above this threshold will trigger a hard <code>BLOCK</code> action.
            </p>
          </div>

          <div className="space-y-3 bg-[#09090B] p-3.5 rounded border border-[#27272A]">
            <div className="flex items-center justify-between text-xs font-semibold text-[#FAFAFA] font-mono">
              <span>Sanitize Risk Threshold</span>
              <span className="text-[#10B981] font-bold">
                {config.sanitizeRiskThreshold.toFixed(2)}
              </span>
            </div>
            <input
              type="range"
              min="0.1"
              max="0.8"
              step="0.05"
              value={config.sanitizeRiskThreshold}
              onChange={(e) => setConfig({ ...config, sanitizeRiskThreshold: parseFloat(e.target.value) })}
              className="w-full accent-[#10B981] cursor-pointer"
            />
            <p className="text-[11px] text-[#71717A] font-mono">
              Payloads above this threshold will be enclosed in cryptographic container boundaries.
            </p>
          </div>

          {/* Layer Activation Toggles */}
          <div className="space-y-2 bg-[#09090B] p-3.5 rounded border border-[#27272A] text-xs font-mono">
            <div className="font-semibold text-[#FAFAFA] mb-2 uppercase tracking-wider text-[11px]">Defense Layer Toggles:</div>

            <label className="flex items-center justify-between p-2 rounded hover:bg-[#18181B] cursor-pointer transition-colors">
              <span className="text-[#E4E4E7]">L1: Homoglyph Normalization</span>
              <input
                type="checkbox"
                checked={config.enableHomoglyphNorm}
                onChange={(e) => setConfig({ ...config, enableHomoglyphNorm: e.target.checked })}
                className="rounded border-[#27272A] text-[#10B981] focus:ring-[#10B981] bg-[#09090B]"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded hover:bg-[#18181B] cursor-pointer transition-colors">
              <span className="text-[#E4E4E7]">L1: Zero-Width & BiDi Strip</span>
              <input
                type="checkbox"
                checked={config.enableEvilUnicodeStrip}
                onChange={(e) => setConfig({ ...config, enableEvilUnicodeStrip: e.target.checked })}
                className="rounded border-[#27272A] text-[#10B981] focus:ring-[#10B981] bg-[#09090B]"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded hover:bg-[#18181B] cursor-pointer transition-colors">
              <span className="text-[#E4E4E7]">L1: Recursive Nested Unpack (Base64/Hex/URL)</span>
              <input
                type="checkbox"
                checked={config.enableRecursiveDecode}
                onChange={(e) => setConfig({ ...config, enableRecursiveDecode: e.target.checked })}
                className="rounded border-[#27272A] text-[#10B981] focus:ring-[#10B981] bg-[#09090B]"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded hover:bg-[#18181B] cursor-pointer transition-colors">
              <span className="text-[#E4E4E7]">L2: Model Delimiter Scanning (ChatML, LLaMA)</span>
              <input
                type="checkbox"
                checked={config.enableDelimiterScan}
                onChange={(e) => setConfig({ ...config, enableDelimiterScan: e.target.checked })}
                className="rounded border-[#27272A] text-[#10B981] focus:ring-[#10B981] bg-[#09090B]"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded hover:bg-[#18181B] cursor-pointer transition-colors">
              <span className="text-[#E4E4E7]">L3: Indirect Role Hijack & Exfiltration Scanner</span>
              <input
                type="checkbox"
                checked={config.enableRoleOverrideScan}
                onChange={(e) => setConfig({ ...config, enableRoleOverrideScan: e.target.checked })}
                className="rounded border-[#27272A] text-[#10B981] focus:ring-[#10B981] bg-[#09090B]"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded hover:bg-[#18181B] cursor-pointer transition-colors">
              <span className="text-[#E4E4E7]">L4: Static AST Code Security Auditor</span>
              <input
                type="checkbox"
                checked={config.enableAstAudit}
                onChange={(e) => setConfig({ ...config, enableAstAudit: e.target.checked })}
                className="rounded border-[#27272A] text-[#10B981] focus:ring-[#10B981] bg-[#09090B]"
              />
            </label>

            <label className="flex items-center justify-between p-2 rounded hover:bg-[#18181B] cursor-pointer transition-colors">
              <span className="text-[#E4E4E7]">L5: Strict Taint Privilege Policy</span>
              <input
                type="checkbox"
                checked={config.strictTaintPolicy}
                onChange={(e) => setConfig({ ...config, strictTaintPolicy: e.target.checked })}
                className="rounded border-[#27272A] text-[#10B981] focus:ring-[#10B981] bg-[#09090B]"
              />
            </label>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-[#27272A]">
          <button
            onClick={handleReset}
            className="text-xs text-[#71717A] hover:text-[#FAFAFA] flex items-center space-x-1 font-mono transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>

          <div className="flex items-center space-x-2 font-mono">
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded text-xs text-[#71717A] hover:text-[#FAFAFA] hover:bg-[#27272A] transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-1.5 rounded bg-[#10B981] hover:bg-[#059669] text-black text-xs font-mono font-bold transition-colors shadow flex items-center space-x-1"
            >
              <Check className="w-3.5 h-3.5" />
              <span>Apply Policies</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
