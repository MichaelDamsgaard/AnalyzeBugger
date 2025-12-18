import { useSessionStore } from "../../stores/sessionStore";
import { useAnalysisStore } from "../../stores/analysisStore";

export function StatusBar() {
  const { status, error, clearError } = useSessionStore();
  const { result } = useAnalysisStore();

  const session = status?.session;

  // Get architecture from actual analysis result
  const arch = result?.file_info?.arch || null;

  return (
    <div className="h-6 bg-bg-secondary border-t border-border flex items-center px-3 text-xs no-select">
      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-2 text-accent-red">
          <span>{error}</span>
          <button
            onClick={clearError}
            className="hover:underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Session Info */}
      {!error && session && (
        <div className="flex items-center gap-4 text-text-secondary">
          <span>RIP: <span className="text-accent-blue font-mono">{session.current_ip || "N/A"}</span></span>
          <span>Modules: {session.module_count || 0}</span>
          <span>Breakpoints: {session.breakpoint_count || 0}</span>
        </div>
      )}

      {/* No Session */}
      {!error && !session && (
        <span className="text-text-secondary">Ready</span>
      )}

      {/* Spacer */}
      <div className="flex-1" />

      {/* Right Side Info - only show arch if we have real data */}
      <div className="flex items-center gap-4 text-text-secondary">
        {arch && <span>{arch}</span>}
        <span>AnalyzeBugger v0.1.0</span>
      </div>
    </div>
  );
}
