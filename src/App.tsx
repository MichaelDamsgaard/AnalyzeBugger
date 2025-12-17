import { useState, useEffect } from "react";
import { Panel, PanelGroup, PanelResizeHandle } from "react-resizable-panels";
import { Toolbar } from "./components/layout/Toolbar";
import { StatusBar } from "./components/layout/StatusBar";
import { DisassemblyView } from "./components/debug/DisassemblyView";
import { RegisterPanel } from "./components/debug/RegisterPanel";
import { CpuPanel } from "./components/debug/CpuPanel";
import { StackPanel } from "./components/debug/StackPanel";
import { MemoryViewer } from "./components/debug/MemoryViewer";
import { ModuleList } from "./components/debug/ModuleList";
import { StringsView } from "./components/debug/StringsView";
import { FunctionsPanel } from "./components/debug/FunctionsPanel";
import { HexView } from "./components/debug/HexView";
import { XrefsPanel } from "./components/debug/XrefsPanel";
import { ImportsPanel } from "./components/debug/ImportsPanel";
import { SectionsPanel } from "./components/debug/SectionsPanel";
import { ExportsPanel } from "./components/debug/ExportsPanel";
import { BreakpointManager } from "./components/debug/BreakpointManager";
import { TracePanel } from "./components/debug/TracePanel";
import { IntelPTPanel } from "./components/debug/IntelPTPanel";
import { PatchEditor } from "./components/debug/PatchEditor";
// ChatPanel available but not currently used in tabs
// import { ChatPanel } from "./components/claude/ChatPanel";
import { NarrativePanel, MitrePanel, IocPanel, AnalysisSidebar } from "./components/analysis";
import { SemanticAnalyzer, AIQueryPanel, ReportGenerator, VulnerabilityScanner, AutoLabeler, AutonomousAnalyst, FunctionSimilarity, BehavioralPredictor } from "./components/ai";
import { useSessionStore } from "./stores/sessionStore";

type MainTab = "disasm" | "hex" | "memory" | "strings" | "patch";
type LeftTab = "functions" | "imports" | "exports" | "sections" | "modules";
type RightTab = "analyst" | "ai-query" | "semantic" | "vulns" | "labels" | "similarity" | "behavior" | "report" | "narrative" | "mitre" | "iocs";
type BottomTab = "trace" | "intelpt" | "cpu" | "stack" | "xrefs" | "breakpoints" | "registers";

function App() {
  const { status, fetchStatus } = useSessionStore();
  const [mainTab, setMainTab] = useState<MainTab>("disasm");
  const [leftTab, setLeftTab] = useState<LeftTab>("functions");
  const [rightTab, setRightTab] = useState<RightTab>("analyst");
  const [bottomTab, setBottomTab] = useState<BottomTab>("trace");
  const [showSidebar, setShowSidebar] = useState(true);

  useEffect(() => {
    // Fetch initial status
    fetchStatus();

    // Poll for status updates every 500ms when debugging
    const interval = setInterval(() => {
      if (status?.session) {
        fetchStatus();
      }
    }, 500);

    return () => clearInterval(interval);
  }, [status?.session]);

  return (
    <div className="h-screen w-screen flex flex-col bg-bg-primary text-text-primary font-mono">
      {/* Toolbar */}
      <Toolbar />

      {/* Main Content */}
      <div className="flex-1 overflow-hidden">
        <PanelGroup direction="horizontal">
          {/* Left Sidebar - Functions/Modules/Analysis */}
          {showSidebar && (
            <>
              <Panel defaultSize={18} minSize={12} maxSize={25}>
                <PanelGroup direction="vertical">
                  {/* Functions/Modules tabs */}
                  <Panel defaultSize={50} minSize={20}>
                    <div className="h-full border-r border-border flex flex-col">
                      <div className="h-8 bg-bg-secondary border-b border-border flex items-center px-2 gap-1 overflow-x-auto">
                        <TabButton
                          active={leftTab === "functions"}
                          onClick={() => setLeftTab("functions")}
                        >
                          Functions
                        </TabButton>
                        <TabButton
                          active={leftTab === "imports"}
                          onClick={() => setLeftTab("imports")}
                        >
                          Imports
                        </TabButton>
                        <TabButton
                          active={leftTab === "exports"}
                          onClick={() => setLeftTab("exports")}
                        >
                          Exports
                        </TabButton>
                        <TabButton
                          active={leftTab === "sections"}
                          onClick={() => setLeftTab("sections")}
                        >
                          Sections
                        </TabButton>
                        <TabButton
                          active={leftTab === "modules"}
                          onClick={() => setLeftTab("modules")}
                        >
                          Modules
                        </TabButton>
                      </div>
                      <div className="flex-1 overflow-hidden">
                        {leftTab === "functions" && <FunctionsPanel />}
                        {leftTab === "imports" && <ImportsPanel />}
                        {leftTab === "exports" && <ExportsPanel />}
                        {leftTab === "sections" && <SectionsPanel />}
                        {leftTab === "modules" && <ModuleList />}
                      </div>
                    </div>
                  </Panel>
                  <PanelResizeHandle className="h-1 bg-border hover:bg-accent-blue transition-colors cursor-row-resize" />
                  {/* Analysis Sidebar */}
                  <Panel defaultSize={50} minSize={20}>
                    <div className="h-full border-r border-border">
                      <AnalysisSidebar />
                    </div>
                  </Panel>
                </PanelGroup>
              </Panel>
              <PanelResizeHandle className="w-1 bg-border hover:bg-accent-blue transition-colors cursor-col-resize" />
            </>
          )}

          {/* Center Panel - Code/Data View */}
          <Panel defaultSize={showSidebar ? 42 : 50} minSize={30}>
            <PanelGroup direction="vertical">
              {/* Tab Bar */}
              <div className="h-9 bg-bg-secondary border-b border-border flex items-center justify-between px-2">
                <div className="flex items-center gap-1">
                  <TabButton
                    active={mainTab === "disasm"}
                    onClick={() => setMainTab("disasm")}
                  >
                    Disassembly
                  </TabButton>
                  <TabButton
                    active={mainTab === "hex"}
                    onClick={() => setMainTab("hex")}
                  >
                    Hex
                  </TabButton>
                  <TabButton
                    active={mainTab === "memory"}
                    onClick={() => setMainTab("memory")}
                  >
                    Memory
                  </TabButton>
                  <TabButton
                    active={mainTab === "strings"}
                    onClick={() => setMainTab("strings")}
                  >
                    Strings
                  </TabButton>
                  <TabButton
                    active={mainTab === "patch"}
                    onClick={() => setMainTab("patch")}
                    highlight
                  >
                    Patch
                  </TabButton>
                </div>
                <button
                  onClick={() => setShowSidebar(!showSidebar)}
                  className="px-2 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
                >
                  {showSidebar ? "Hide Sidebar" : "Show Sidebar"}
                </button>
              </div>

              {/* Main Content Area */}
              <Panel defaultSize={60}>
                <div className="h-full overflow-hidden">
                  {mainTab === "disasm" && <DisassemblyView />}
                  {mainTab === "hex" && <HexView />}
                  {mainTab === "memory" && <MemoryViewer />}
                  {mainTab === "strings" && <StringsView />}
                  {mainTab === "patch" && <PatchEditor />}
                </div>
              </Panel>

              <PanelResizeHandle className="h-1 bg-border hover:bg-accent-blue transition-colors cursor-row-resize" />

              {/* Bottom Panel - CPU/Stack/Registers */}
              <Panel defaultSize={40} minSize={15}>
                <div className="h-full flex flex-col">
                  <div className="h-8 bg-bg-secondary border-b border-border flex items-center px-2 gap-1">
                    <TabButton
                      active={bottomTab === "trace"}
                      onClick={() => setBottomTab("trace")}
                      highlight
                    >
                      Trace
                    </TabButton>
                    <TabButton
                      active={bottomTab === "intelpt"}
                      onClick={() => setBottomTab("intelpt")}
                      highlight
                    >
                      Intel PT
                    </TabButton>
                    <TabButton
                      active={bottomTab === "cpu"}
                      onClick={() => setBottomTab("cpu")}
                    >
                      CPU
                    </TabButton>
                    <TabButton
                      active={bottomTab === "stack"}
                      onClick={() => setBottomTab("stack")}
                    >
                      Stack
                    </TabButton>
                    <TabButton
                      active={bottomTab === "xrefs"}
                      onClick={() => setBottomTab("xrefs")}
                    >
                      Xrefs
                    </TabButton>
                    <TabButton
                      active={bottomTab === "breakpoints"}
                      onClick={() => setBottomTab("breakpoints")}
                    >
                      Breakpoints
                    </TabButton>
                    <TabButton
                      active={bottomTab === "registers"}
                      onClick={() => setBottomTab("registers")}
                    >
                      Registers
                    </TabButton>
                  </div>
                  <div className="flex-1 overflow-auto">
                    {bottomTab === "trace" && <TracePanel />}
                    {bottomTab === "intelpt" && <IntelPTPanel />}
                    {bottomTab === "cpu" && <CpuPanel />}
                    {bottomTab === "stack" && <StackPanel />}
                    {bottomTab === "xrefs" && <XrefsPanel />}
                    {bottomTab === "breakpoints" && <BreakpointManager />}
                    {bottomTab === "registers" && <RegisterPanel />}
                  </div>
                </div>
              </Panel>
            </PanelGroup>
          </Panel>

          <PanelResizeHandle className="w-1 bg-border hover:bg-accent-blue transition-colors cursor-col-resize" />

          {/* Right Panel - AI Analysis & Findings */}
          <Panel defaultSize={40} minSize={25}>
            <PanelGroup direction="vertical">
              {/* Tab Bar for Right Panel */}
              <div className="h-9 bg-bg-secondary border-b border-border flex items-center px-2 gap-1 overflow-x-auto">
                <TabButton
                  active={rightTab === "analyst"}
                  onClick={() => setRightTab("analyst")}
                  highlight
                >
                  AI Analyst
                </TabButton>
                <TabButton
                  active={rightTab === "ai-query"}
                  onClick={() => setRightTab("ai-query")}
                  highlight
                >
                  Ask AI
                </TabButton>
                <TabButton
                  active={rightTab === "semantic"}
                  onClick={() => setRightTab("semantic")}
                  highlight
                >
                  Semantic
                </TabButton>
                <TabButton
                  active={rightTab === "vulns"}
                  onClick={() => setRightTab("vulns")}
                  highlight
                >
                  Vulns
                </TabButton>
                <TabButton
                  active={rightTab === "labels"}
                  onClick={() => setRightTab("labels")}
                  highlight
                >
                  Labels
                </TabButton>
                <TabButton
                  active={rightTab === "similarity"}
                  onClick={() => setRightTab("similarity")}
                  highlight
                >
                  Similar
                </TabButton>
                <TabButton
                  active={rightTab === "behavior"}
                  onClick={() => setRightTab("behavior")}
                  highlight
                >
                  Predict
                </TabButton>
                <TabButton
                  active={rightTab === "report"}
                  onClick={() => setRightTab("report")}
                >
                  Report
                </TabButton>
                <TabButton
                  active={rightTab === "narrative"}
                  onClick={() => setRightTab("narrative")}
                >
                  Narrative
                </TabButton>
                <TabButton
                  active={rightTab === "mitre"}
                  onClick={() => setRightTab("mitre")}
                >
                  MITRE
                </TabButton>
                <TabButton
                  active={rightTab === "iocs"}
                  onClick={() => setRightTab("iocs")}
                >
                  IOCs
                </TabButton>
              </div>

              {/* AI/Analysis Content */}
              <Panel defaultSize={100}>
                <div className="h-full overflow-hidden">
                  {rightTab === "analyst" && <AutonomousAnalyst />}
                  {rightTab === "ai-query" && <AIQueryPanel />}
                  {rightTab === "semantic" && <SemanticAnalyzer />}
                  {rightTab === "vulns" && <VulnerabilityScanner />}
                  {rightTab === "labels" && <AutoLabeler />}
                  {rightTab === "similarity" && <FunctionSimilarity />}
                  {rightTab === "behavior" && <BehavioralPredictor />}
                  {rightTab === "report" && <ReportGenerator />}
                  {rightTab === "narrative" && <NarrativePanel />}
                  {rightTab === "mitre" && <MitrePanel />}
                  {rightTab === "iocs" && <IocPanel />}
                </div>
              </Panel>
            </PanelGroup>
          </Panel>
        </PanelGroup>
      </div>

      {/* Status Bar */}
      <StatusBar />
    </div>
  );
}

function TabButton({
  active,
  onClick,
  highlight,
  children,
}: {
  active: boolean;
  onClick: () => void;
  highlight?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1 text-xs rounded transition-colors ${
        active
          ? highlight
            ? "bg-accent-purple/20 text-accent-purple border border-accent-purple/30"
            : "bg-bg-tertiary text-text-primary"
          : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
      }`}
    >
      {children}
    </button>
  );
}

export default App;
