import { useState, useMemo } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import { Binary, Search, ArrowUp, ArrowDown } from "lucide-react";

export function HexView() {
  const { result } = useAnalysisStore();
  const [offset, setOffset] = useState(0);
  const [bytesPerRow] = useState(16);
  const [searchHex, setSearchHex] = useState("");

  // We need raw bytes - for now reconstruct from instructions
  // In production, we'd have the raw file data available
  const rawBytes = useMemo(() => {
    if (!result?.instructions) return [];

    const bytes: number[] = [];
    result.instructions.forEach(insn => {
      const hexBytes = insn.bytes.split(" ");
      hexBytes.forEach(hex => {
        if (hex) bytes.push(parseInt(hex, 16));
      });
    });
    return bytes;
  }, [result?.instructions]);

  const baseAddress = result?.file_info.base_address
    ? parseInt(result.file_info.base_address, 16)
    : 0x100;

  // Generate hex rows
  const rows = useMemo(() => {
    const result: { address: string; hex: string[]; ascii: string }[] = [];

    for (let i = offset; i < rawBytes.length; i += bytesPerRow) {
      const rowBytes = rawBytes.slice(i, i + bytesPerRow);
      const address = (baseAddress + i).toString(16).toUpperCase().padStart(4, "0");

      const hex = rowBytes.map(b => b.toString(16).toUpperCase().padStart(2, "0"));
      // Pad to full row
      while (hex.length < bytesPerRow) {
        hex.push("  ");
      }

      const ascii = rowBytes
        .map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".")
        .join("");

      result.push({ address, hex, ascii });

      // Limit visible rows for performance
      if (result.length >= 100) break;
    }

    return result;
  }, [rawBytes, offset, bytesPerRow, baseAddress]);

  const handleScroll = (direction: "up" | "down") => {
    const step = bytesPerRow * 10;
    if (direction === "up") {
      setOffset(Math.max(0, offset - step));
    } else {
      setOffset(Math.min(rawBytes.length - bytesPerRow, offset + step));
    }
  };

  if (!result || rawBytes.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <Binary className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No hex data</p>
          <p className="text-xs mt-1">Analyze a file to view hex</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="h-8 bg-bg-secondary border-b border-border flex items-center justify-between px-3">
        <div className="flex items-center gap-2">
          <Binary className="w-4 h-4 text-accent-orange" />
          <span className="text-sm font-medium">Hex View</span>
          <span className="text-xs text-text-secondary">
            {rawBytes.length} bytes
          </span>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => handleScroll("up")}
            disabled={offset === 0}
            className="p-1 hover:bg-bg-hover rounded disabled:opacity-30"
          >
            <ArrowUp className="w-3 h-3" />
          </button>
          <button
            onClick={() => handleScroll("down")}
            disabled={offset >= rawBytes.length - bytesPerRow}
            className="p-1 hover:bg-bg-hover rounded disabled:opacity-30"
          >
            <ArrowDown className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Search */}
      <div className="h-8 bg-bg-tertiary border-b border-border flex items-center px-2 gap-2">
        <Search className="w-3 h-3 text-text-secondary" />
        <input
          type="text"
          value={searchHex}
          onChange={(e) => setSearchHex(e.target.value)}
          placeholder="Search hex (e.g., CD 21)..."
          className="flex-1 bg-transparent text-xs font-mono focus:outline-none"
        />
      </div>

      {/* Column headers */}
      <div className="h-6 bg-bg-tertiary border-b border-border flex items-center px-2 font-mono text-[10px] text-text-secondary">
        <span className="w-12">Offset</span>
        <span className="flex-1">
          {Array.from({ length: bytesPerRow }, (_, i) =>
            i.toString(16).toUpperCase().padStart(2, "0")
          ).join(" ")}
        </span>
        <span className="w-20 text-center">ASCII</span>
      </div>

      {/* Hex content */}
      <div className="flex-1 overflow-auto font-mono text-xs">
        {rows.map((row, idx) => (
          <div
            key={idx}
            className="flex items-center px-2 py-0.5 hover:bg-bg-hover border-b border-border/30"
          >
            {/* Address */}
            <span className="w-12 text-accent-blue">{row.address}</span>

            {/* Hex bytes */}
            <span className="flex-1 flex gap-[2px]">
              {row.hex.map((byte, byteIdx) => (
                <span
                  key={byteIdx}
                  className={`w-5 text-center ${
                    byte === "  " ? "" :
                    byte === "00" ? "text-text-secondary" :
                    byte === "CC" || byte === "CD" ? "text-accent-red" :
                    byte === "90" ? "text-text-secondary" :
                    parseInt(byte, 16) >= 0x20 && parseInt(byte, 16) < 0x7f
                      ? "text-text-primary"
                      : "text-accent-yellow"
                  }`}
                >
                  {byte}
                </span>
              ))}
            </span>

            {/* ASCII */}
            <span className="w-20 text-accent-green bg-bg-tertiary px-1 rounded">
              {row.ascii}
            </span>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="h-6 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary">
        <span>
          Showing {offset.toString(16).toUpperCase()}-
          {Math.min(offset + rows.length * bytesPerRow, rawBytes.length).toString(16).toUpperCase()}
        </span>
        <span>Base: {result.file_info.base_address}</span>
      </div>
    </div>
  );
}
