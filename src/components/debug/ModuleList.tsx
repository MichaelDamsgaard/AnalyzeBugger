import { useSessionStore } from "../../stores/sessionStore";
import { Package } from "lucide-react";

export function ModuleList() {
  const { modules } = useSessionStore();

  if (modules.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Package className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>No modules loaded</p>
          <p className="text-xs mt-1">Launch a target to see loaded modules</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <table className="w-full font-mono text-xs">
        <thead className="sticky top-0 bg-bg-secondary">
          <tr className="text-text-secondary">
            <th className="px-3 py-2 text-left">Name</th>
            <th className="px-3 py-2 text-left">Base Address</th>
            <th className="px-3 py-2 text-right">Size</th>
            <th className="px-3 py-2 text-left">Entry Point</th>
          </tr>
        </thead>
        <tbody>
          {modules.map((mod, idx) => (
            <tr key={idx} className="hover:bg-bg-hover border-b border-border/50">
              <td className="px-3 py-1.5 text-text-primary">
                <div className="flex items-center gap-2">
                  <Package className="w-3 h-3 text-accent-blue" />
                  {mod.name}
                </div>
              </td>
              <td className="px-3 py-1.5 text-accent-blue">
                {mod.base}
              </td>
              <td className="px-3 py-1.5 text-right text-text-secondary">
                {formatSize(mod.size)}
              </td>
              <td className="px-3 py-1.5 text-accent-green">
                {mod.entry}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
