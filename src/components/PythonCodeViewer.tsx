import React, { useState } from 'react';
import {
  Code2,
  Copy,
  Check,
  Download,
  FolderTree,
  FileCode,
  Terminal,
  Shield,
  Layers,
  CheckCircle2,
  FileSpreadsheet,
} from 'lucide-react';
import { ENTERPRISE_PROJECT_FILES, PYTHON_KERNEL_SOURCE, PythonFileSpec } from '../data/pythonSource';

export const PythonCodeViewer: React.FC = () => {
  const [selectedFileId, setSelectedFileId] = useState<string>('setup-ps1');
  const [copied, setCopied] = useState<boolean>(false);
  const [copiedSetupCmd, setCopiedSetupCmd] = useState<string | null>(null);

  const currentFile: PythonFileSpec =
    ENTERPRISE_PROJECT_FILES.find((f) => f.id === selectedFileId) || ENTERPRISE_PROJECT_FILES[0];

  const handleCopyCurrent = () => {
    navigator.clipboard.writeText(currentFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadCurrent = () => {
    const element = document.createElement('a');
    const isPs1 = currentFile.name.endsWith('.ps1');
    const file = new Blob([currentFile.content], {
      type: isPs1 ? 'text/plain' : 'text/x-python',
    });
    element.href = URL.createObjectURL(file);
    element.download = currentFile.name;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  const handleCopyCommand = (cmd: string, key: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedSetupCmd(key);
    setTimeout(() => setCopiedSetupCmd(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Info Banner */}
      <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-5 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-mono text-xs font-bold text-[#A1A1AA] uppercase tracking-widest flex items-center space-x-2">
                <FolderTree className="w-4 h-4 text-[#10B981]" />
                <span>PromptGuard-Taint Enterprise Architecture</span>
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#09090B] text-[#10B981] border border-[#27272A]">
                Python 3.8+ • Enterprise Modular
              </span>
            </div>
            <p className="text-xs text-[#71717A] mt-1 font-mono">
              Complete production package with AST sandbox, lexical normalizer, FastAPI middleware, and automated scaffolding.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopyCurrent}
              className="px-3 py-2 rounded bg-[#09090B] hover:bg-[#27272A] text-[#71717A] hover:text-[#FAFAFA] border border-[#27272A] text-xs font-mono flex items-center space-x-1.5 transition-colors"
            >
              {copied ? <Check className="w-4 h-4 text-[#10B981]" /> : <Copy className="w-4 h-4" />}
              <span>{copied ? 'Copied' : `Copy ${currentFile.name}`}</span>
            </button>
            <button
              onClick={handleDownloadCurrent}
              className="px-3 py-2 rounded bg-[#10B981] hover:bg-[#059669] text-black text-xs font-mono font-bold flex items-center space-x-1.5 transition-colors shadow"
            >
              <Download className="w-4 h-4" />
              <span>Download {currentFile.name}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Quick Setup & Test Commands */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* PowerShell Scaffolding */}
        <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 font-mono text-xs text-[#E4E4E7] space-y-2">
          <div className="flex items-center justify-between text-[#71717A] text-[10px] uppercase tracking-widest font-bold">
            <span>PowerShell Setup Script</span>
            <button
              onClick={() => handleCopyCommand('.\\setup_promptguard.ps1', 'ps1')}
              className="hover:text-[#FAFAFA] text-[11px] flex items-center space-x-1"
            >
              {copiedSetupCmd === 'ps1' ? <Check className="w-3 h-3 text-[#10B981]" /> : <Copy className="w-3 h-3" />}
              <span>Copy</span>
            </button>
          </div>
          <div className="bg-[#09090B] p-2.5 rounded border border-[#27272A] text-[#10B981]">
            <code>pwsh -ExecutionPolicy Bypass -File .\\setup_promptguard.ps1</code>
          </div>
        </div>

        {/* Pytest Execution */}
        <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-4 font-mono text-xs text-[#E4E4E7] space-y-2">
          <div className="flex items-center justify-between text-[#71717A] text-[10px] uppercase tracking-widest font-bold">
            <span>Run Test Suite (Pytest / Unittest)</span>
            <button
              onClick={() => handleCopyCommand('python3 -m unittest -v tests/test_deterministic_suite.py', 'test')}
              className="hover:text-[#FAFAFA] text-[11px] flex items-center space-x-1"
            >
              {copiedSetupCmd === 'test' ? <Check className="w-3 h-3 text-[#10B981]" /> : <Copy className="w-3 h-3" />}
              <span>Copy</span>
            </button>
          </div>
          <div className="bg-[#09090B] p-2.5 rounded border border-[#27272A] text-[#10B981]">
            <code>pytest tests -v  # or: python3 -m unittest discover tests</code>
          </div>
        </div>
      </div>

      {/* Modular File Explorer & Code Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Left Sidebar: File Tree */}
        <div className="bg-[#18181B] border border-[#27272A] rounded-lg p-3 space-y-3 font-mono">
          <div className="text-[10px] uppercase tracking-widest text-[#71717A] font-bold px-2">
            Project Files ({ENTERPRISE_PROJECT_FILES.length})
          </div>

          <div className="space-y-1">
            {ENTERPRISE_PROJECT_FILES.map((file) => {
              const isSelected = file.id === selectedFileId;
              return (
                <button
                  key={file.id}
                  onClick={() => setSelectedFileId(file.id)}
                  className={`w-full text-left px-2.5 py-2 rounded text-xs transition-colors flex items-center space-x-2 ${
                    isSelected
                      ? 'bg-[#10B981]/15 text-[#10B981] border border-[#10B981]/30 font-bold'
                      : 'text-[#A1A1AA] hover:bg-[#27272A] hover:text-[#FAFAFA]'
                  }`}
                >
                  <FileCode className={`w-3.5 h-3.5 ${isSelected ? 'text-[#10B981]' : 'text-[#71717A]'}`} />
                  <div className="truncate">
                    <div className="truncate">{file.path}</div>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="pt-2 border-t border-[#27272A] px-2 text-[11px] text-[#71717A]">
            Selected: <span className="text-[#FAFAFA]">{currentFile.name}</span>
            <p className="text-[10px] text-[#52525B] mt-0.5">{currentFile.description}</p>
          </div>
        </div>

        {/* Right Code Display */}
        <div className="lg:col-span-3 bg-[#09090B] border border-[#27272A] rounded-lg overflow-hidden shadow-sm flex flex-col">
          <div className="bg-[#18181B] px-4 py-2.5 border-b border-[#27272A] flex items-center justify-between text-xs font-mono text-[#71717A]">
            <div className="flex items-center space-x-2">
              <div className="w-2.5 h-2.5 rounded-full bg-[#F43F5E]"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]"></div>
              <div className="w-2.5 h-2.5 rounded-full bg-[#10B981]"></div>
              <span className="ml-2 text-[#FAFAFA] font-bold">{currentFile.path}</span>
            </div>
            <span className="text-[11px] text-[#71717A]">{currentFile.description}</span>
          </div>

          <pre className="p-4 text-xs font-mono text-[#FAFAFA] overflow-x-auto leading-relaxed max-h-[620px] overflow-y-auto flex-1">
            {currentFile.content}
          </pre>
        </div>
      </div>
    </div>
  );
};

