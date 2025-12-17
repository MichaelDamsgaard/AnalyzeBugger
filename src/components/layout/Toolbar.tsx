import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Play,
  Pause,
  Square,
  StepForward,
  ArrowDownToLine,
  FolderOpen,
  Bug,
  Cpu,
  FileSearch,
} from "lucide-react";
import { useSessionStore } from "../../stores/sessionStore";
import { useAnalysisStore } from "../../stores/analysisStore";

export function Toolbar() {
  const {
    status,
    launchTarget,
    stopSession,
    continueExecution,
    pauseExecution,
    stepInto,
    stepOver,
    isLoading,
  } = useSessionStore();

  const {
    analyzeFile,
    clearAnalysis,
    result: analysisResult,
    isAnalyzing,
  } = useAnalysisStore();

  const [targetPath, setTargetPath] = useState("");

  const session = status?.session;
  const isRunning = session?.state === "running";
  const isPaused = session?.state === "paused" || session?.state === "stepping";
  const hasSession = !!session;
  const hasAnalysis = !!analysisResult;

  // Check if file is a static-analysis-only type (COM, raw binary)
  const isStaticOnlyFile = (path: string) => {
    const lower = path.toLowerCase();
    return lower.endsWith(".com") || lower.endsWith(".bin") || lower.endsWith(".raw");
  };

  const handleOpenFile = async () => {
    const selected = await open({
      multiple: false,
      filters: [
        { name: "Executables", extensions: ["exe", "dll", "com", "bin"] },
        { name: "All Files", extensions: ["*"] },
      ],
    });
    if (selected) {
      setTargetPath(selected as string);
    }
  };

  const handleAnalyze = async () => {
    if (targetPath) {
      await analyzeFile(targetPath);
    }
  };

  const handleLaunch = async () => {
    if (targetPath) {
      await launchTarget(targetPath);
    }
  };

  const handleClearAnalysis = () => {
    clearAnalysis();
    setTargetPath("");
  };

  return (
    <div className="h-10 bg-bg-secondary border-b border-border flex items-center px-2 gap-2 no-select">
      {/* Logo */}
      <div className="flex items-center gap-2 px-2 border-r border-border mr-2">
        <Bug className="w-5 h-5 text-accent-green" />
        <span className="text-sm font-bold text-text-primary">AnalyzeBugger</span>
      </div>

      {/* File Selection */}
      <div className="flex items-center gap-1">
        <button
          onClick={handleOpenFile}
          className="p-1.5 rounded hover:bg-bg-hover transition-colors"
          title="Open File"
        >
          <FolderOpen className="w-4 h-4" />
        </button>
        <input
          type="text"
          value={targetPath}
          onChange={(e) => setTargetPath(e.target.value)}
          placeholder="Select executable..."
          className="w-64 px-2 py-1 text-xs bg-bg-tertiary border border-border rounded focus:border-accent-blue focus:outline-none"
        />

        {/* Analyze button - for static analysis */}
        <button
          onClick={handleAnalyze}
          disabled={!targetPath || isAnalyzing || hasAnalysis}
          className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-purple text-white rounded hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
          title="Static Analysis (no execution)"
        >
          <FileSearch className="w-3 h-3" />
          Analyze
        </button>

        {/* Debug button - for live debugging (PE only) */}
        {!isStaticOnlyFile(targetPath) && (
          <button
            onClick={handleLaunch}
            disabled={!targetPath || isLoading || hasSession || hasAnalysis}
            className="flex items-center gap-1 px-3 py-1 text-xs bg-accent-green text-bg-primary rounded hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed transition-opacity"
            title="Debug (execute with breakpoints)"
          >
            <Bug className="w-3 h-3" />
            Debug
          </button>
        )}

        {/* Clear button when analysis is loaded */}
        {hasAnalysis && (
          <button
            onClick={handleClearAnalysis}
            className="px-2 py-1 text-xs bg-bg-tertiary text-text-secondary rounded hover:bg-accent-red/20 hover:text-accent-red transition-colors"
            title="Close analysis"
          >
            Close
          </button>
        )}
      </div>

      {/* Separator */}
      <div className="w-px h-6 bg-border mx-2" />

      {/* Debug Controls */}
      <div className="flex items-center gap-1">
        <ToolbarButton
          icon={<Play className="w-4 h-4" />}
          onClick={continueExecution}
          disabled={!isPaused}
          title="Continue (F5)"
          active={false}
        />
        <ToolbarButton
          icon={<Pause className="w-4 h-4" />}
          onClick={pauseExecution}
          disabled={!isRunning}
          title="Pause"
          active={false}
        />
        <ToolbarButton
          icon={<Square className="w-4 h-4" />}
          onClick={stopSession}
          disabled={!hasSession}
          title="Stop (Shift+F5)"
          active={false}
          destructive
        />

        <div className="w-px h-6 bg-border mx-1" />

        <ToolbarButton
          icon={<ArrowDownToLine className="w-4 h-4" />}
          onClick={stepInto}
          disabled={!isPaused}
          title="Step Into (F11)"
          active={false}
        />
        <ToolbarButton
          icon={<StepForward className="w-4 h-4" />}
          onClick={stepOver}
          disabled={!isPaused}
          title="Step Over (F10)"
          active={false}
        />
      </div>

      {/* Separator */}
      <div className="w-px h-6 bg-border mx-2" />

      {/* Session Info */}
      {hasSession && (
        <div className="flex items-center gap-3 text-xs text-text-secondary">
          <div className="flex items-center gap-1">
            <Cpu className="w-3 h-3" />
            <span>PID: {session.process_id || "-"}</span>
          </div>
          <div className={`px-2 py-0.5 rounded text-xs ${
            isRunning ? "bg-accent-green/20 text-accent-green" :
            isPaused ? "bg-accent-yellow/20 text-accent-yellow" :
            "bg-accent-red/20 text-accent-red"
          }`}>
            {session.state}
          </div>
        </div>
      )}

      {/* Analysis Info */}
      {hasAnalysis && analysisResult && (
        <div className="flex items-center gap-3 text-xs text-text-secondary">
          <div className="flex items-center gap-1">
            <FileSearch className="w-3 h-3 text-accent-purple" />
            <span className="text-text-primary">{analysisResult.file_info.name}</span>
          </div>
          <span>{analysisResult.file_info.arch}</span>
          <span>{analysisResult.instruction_count} insns</span>
          <span>{analysisResult.string_count} strings</span>
          <div className={`px-2 py-0.5 rounded text-xs ${
            analysisResult.file_info.is_packed
              ? "bg-accent-yellow/20 text-accent-yellow"
              : "bg-accent-green/20 text-accent-green"
          }`}>
            {analysisResult.file_info.is_packed ? "Packed" : "Clean"}
          </div>
        </div>
      )}

      {/* Spacer */}
      <div className="flex-1" />

      {/* DLL Status */}
      <div className="flex items-center gap-2 text-xs text-text-secondary">
        <div className={`w-2 h-2 rounded-full ${status?.dll_loaded ? "bg-accent-green" : "bg-accent-red"}`} />
        <span>DLL {status?.dll_version || "not loaded"}</span>
      </div>
    </div>
  );
}

function ToolbarButton({
  icon,
  onClick,
  disabled,
  title,
  active,
  destructive,
}: {
  icon: React.ReactNode;
  onClick: () => void;
  disabled: boolean;
  title: string;
  active: boolean;
  destructive?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`p-1.5 rounded transition-colors ${
        disabled
          ? "opacity-30 cursor-not-allowed"
          : destructive
          ? "hover:bg-accent-red/20 hover:text-accent-red"
          : active
          ? "bg-accent-blue/20 text-accent-blue"
          : "hover:bg-bg-hover"
      }`}
    >
      {icon}
    </button>
  );
}
