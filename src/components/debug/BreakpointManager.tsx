import { useState } from "react";
import { useSessionStore } from "../../stores/sessionStore";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Circle, CircleDot, Trash2, Plus, Zap
} from "lucide-react";

interface Breakpoint {
  id: number;
  address: string;
  type: "software" | "hardware_exec" | "hardware_write" | "hardware_rw";
  enabled: boolean;
  hitCount: number;
  condition?: string;
  label?: string;
}

// Demo breakpoints for static analysis mode
const STATIC_BREAKPOINTS: Breakpoint[] = [];

export function BreakpointManager() {
  const { status } = useSessionStore();
  const { navigateTo, labels } = useAnalysisStore();
  const [breakpoints, setBreakpoints] = useState<Breakpoint[]>(STATIC_BREAKPOINTS);
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newBpAddress, setNewBpAddress] = useState("");
  const [newBpType, setNewBpType] = useState<Breakpoint["type"]>("software");

  const isDebugging = !!status?.session;

  const addBreakpoint = () => {
    if (!newBpAddress) return;

    const newBp: Breakpoint = {
      id: Date.now(),
      address: newBpAddress.startsWith("0x") ? newBpAddress : `0x${newBpAddress}`,
      type: newBpType,
      enabled: true,
      hitCount: 0,
      label: labels.get(newBpAddress)?.name,
    };

    setBreakpoints([...breakpoints, newBp]);
    setNewBpAddress("");
    setShowAddDialog(false);
  };

  const removeBreakpoint = (id: number) => {
    setBreakpoints(breakpoints.filter(bp => bp.id !== id));
  };

  const toggleBreakpoint = (id: number) => {
    setBreakpoints(breakpoints.map(bp =>
      bp.id === id ? { ...bp, enabled: !bp.enabled } : bp
    ));
  };

  const getTypeInfo = (type: Breakpoint["type"]) => {
    switch (type) {
      case "software": return { label: "SW", color: "text-accent-blue", desc: "Software breakpoint (INT3)" };
      case "hardware_exec": return { label: "HW-X", color: "text-accent-purple", desc: "Hardware execute" };
      case "hardware_write": return { label: "HW-W", color: "text-accent-orange", desc: "Hardware write" };
      case "hardware_rw": return { label: "HW-RW", color: "text-accent-red", desc: "Hardware read/write" };
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <CircleDot className="w-4 h-4 text-accent-red" />
          <span className="text-sm font-medium">Breakpoints</span>
          <span className="text-xs text-text-secondary">
            ({breakpoints.filter(bp => bp.enabled).length}/{breakpoints.length})
          </span>
        </div>
        <button
          onClick={() => setShowAddDialog(true)}
          className="flex items-center gap-1 px-2 py-0.5 text-xs bg-bg-tertiary hover:bg-bg-hover rounded transition-colors"
        >
          <Plus className="w-3 h-3" />
          Add
        </button>
      </div>

      {/* Add breakpoint dialog */}
      {showAddDialog && (
        <div className="bg-bg-tertiary border-b border-border p-3 space-y-2">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={newBpAddress}
              onChange={(e) => setNewBpAddress(e.target.value)}
              placeholder="Address (e.g., 0x401000)"
              className="flex-1 px-2 py-1 text-xs font-mono bg-bg-primary border border-border rounded focus:outline-none focus:border-accent-blue"
              autoFocus
            />
            <select
              value={newBpType}
              onChange={(e) => setNewBpType(e.target.value as Breakpoint["type"])}
              className="px-2 py-1 text-xs bg-bg-primary border border-border rounded"
            >
              <option value="software">Software</option>
              <option value="hardware_exec">HW Execute</option>
              <option value="hardware_write">HW Write</option>
              <option value="hardware_rw">HW Read/Write</option>
            </select>
          </div>
          <div className="flex justify-end gap-2">
            <button
              onClick={() => setShowAddDialog(false)}
              className="px-2 py-1 text-xs text-text-secondary hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              onClick={addBreakpoint}
              className="px-2 py-1 text-xs bg-accent-blue/20 text-accent-blue rounded hover:bg-accent-blue/30"
            >
              Add Breakpoint
            </button>
          </div>
        </div>
      )}

      {/* Breakpoint list */}
      <div className="flex-1 overflow-auto">
        {breakpoints.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            <div className="text-center">
              <Circle className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p className="text-sm">No breakpoints</p>
              <p className="text-xs mt-1">Click "Add" to create a breakpoint</p>
            </div>
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {breakpoints.map((bp) => {
              const typeInfo = getTypeInfo(bp.type);
              return (
                <div
                  key={bp.id}
                  className={`px-3 py-2 flex items-center gap-2 hover:bg-bg-hover transition-colors ${
                    !bp.enabled ? "opacity-50" : ""
                  }`}
                >
                  {/* Enable toggle */}
                  <button
                    onClick={() => toggleBreakpoint(bp.id)}
                    className="p-0.5"
                    title={bp.enabled ? "Disable" : "Enable"}
                  >
                    {bp.enabled ? (
                      <CircleDot className="w-4 h-4 text-accent-red" />
                    ) : (
                      <Circle className="w-4 h-4 text-text-secondary" />
                    )}
                  </button>

                  {/* Type badge */}
                  <span
                    className={`px-1.5 py-0.5 text-[10px] rounded ${typeInfo.color} bg-current/10`}
                    title={typeInfo.desc}
                  >
                    {typeInfo.label}
                  </span>

                  {/* Address */}
                  <button
                    onClick={() => navigateTo(bp.address)}
                    className="font-mono text-xs text-accent-blue hover:underline"
                  >
                    {bp.address}
                  </button>

                  {/* Label */}
                  {bp.label && (
                    <span className="text-xs text-accent-purple truncate max-w-[100px]">
                      {bp.label}
                    </span>
                  )}

                  <span className="flex-1" />

                  {/* Hit count (if debugging) */}
                  {isDebugging && bp.hitCount > 0 && (
                    <span className="text-[10px] text-text-secondary">
                      {bp.hitCount} hits
                    </span>
                  )}

                  {/* Condition indicator */}
                  {bp.condition && (
                    <span title={`Condition: ${bp.condition}`}>
                      <Zap className="w-3 h-3 text-accent-yellow" />
                    </span>
                  )}

                  {/* Actions */}
                  <button
                    onClick={() => removeBreakpoint(bp.id)}
                    className="p-1 hover:bg-bg-tertiary rounded text-text-secondary hover:text-accent-red"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>
          {isDebugging ? "Live debugging" : "Static analysis mode"}
        </span>
        <div className="flex items-center gap-2">
          <button className="hover:text-text-primary">Enable All</button>
          <span>|</span>
          <button className="hover:text-text-primary">Disable All</button>
        </div>
      </div>
    </div>
  );
}
