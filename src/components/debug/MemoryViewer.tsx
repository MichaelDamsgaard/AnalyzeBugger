import { useState } from "react";
import { useSessionStore } from "../../stores/sessionStore";
import { Search } from "lucide-react";

export function MemoryViewer() {
  const { memoryAddress, memoryData, fetchMemory, status } = useSessionStore();
  const [addressInput, setAddressInput] = useState("0x0");
  const [length, setLength] = useState(256);

  const hasSession = !!status?.session;

  const handleFetch = () => {
    if (addressInput) {
      fetchMemory(addressInput, length);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleFetch();
    }
  };

  // Parse hex string to bytes
  const bytes = memoryData
    ? memoryData.split(" ").map((b) => parseInt(b, 16))
    : [];

  return (
    <div className="h-full flex flex-col">
      {/* Address Input */}
      <div className="p-2 border-b border-border flex items-center gap-2">
        <input
          type="text"
          value={addressInput}
          onChange={(e) => setAddressInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Address (0x...)"
          className="flex-1 px-2 py-1 text-xs font-mono bg-bg-tertiary border border-border rounded focus:border-accent-blue focus:outline-none"
        />
        <select
          value={length}
          onChange={(e) => setLength(parseInt(e.target.value))}
          className="px-2 py-1 text-xs bg-bg-tertiary border border-border rounded focus:outline-none"
        >
          <option value={64}>64 bytes</option>
          <option value={128}>128 bytes</option>
          <option value={256}>256 bytes</option>
          <option value={512}>512 bytes</option>
          <option value={1024}>1 KB</option>
        </select>
        <button
          onClick={handleFetch}
          disabled={!hasSession}
          className="p-1.5 rounded bg-accent-blue text-bg-primary hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Search className="w-4 h-4" />
        </button>
      </div>

      {/* Memory Display */}
      <div className="flex-1 overflow-auto font-mono text-xs p-2">
        {bytes.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-secondary">
            Enter an address and click search to view memory
          </div>
        ) : (
          <HexDisplay address={memoryAddress} bytes={bytes} />
        )}
      </div>
    </div>
  );
}

function HexDisplay({ address, bytes }: { address: string; bytes: number[] }) {
  const baseAddr = BigInt(address);
  const bytesPerRow = 16;
  const rows: number[][] = [];

  for (let i = 0; i < bytes.length; i += bytesPerRow) {
    rows.push(bytes.slice(i, i + bytesPerRow));
  }

  return (
    <table className="w-full">
      <thead className="sticky top-0 bg-bg-secondary">
        <tr className="text-text-secondary">
          <th className="w-24 px-2 py-1 text-left">Address</th>
          <th className="px-2 py-1 text-left">Hex</th>
          <th className="w-40 px-2 py-1 text-left">ASCII</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, rowIdx) => {
          const rowAddr = baseAddr + BigInt(rowIdx * bytesPerRow);
          return (
            <tr key={rowIdx} className="hover:bg-bg-hover">
              {/* Address */}
              <td className="w-24 px-2 py-0.5 text-accent-blue">
                0x{rowAddr.toString(16).padStart(16, "0")}
              </td>

              {/* Hex bytes */}
              <td className="px-2 py-0.5">
                <div className="flex gap-1">
                  {row.map((byte, byteIdx) => (
                    <span
                      key={byteIdx}
                      className={byte === 0 ? "text-text-secondary" : "text-text-primary"}
                    >
                      {byte.toString(16).padStart(2, "0").toUpperCase()}
                    </span>
                  ))}
                  {/* Padding for incomplete rows */}
                  {row.length < bytesPerRow &&
                    Array(bytesPerRow - row.length)
                      .fill(0)
                      .map((_, i) => (
                        <span key={`pad-${i}`} className="text-transparent">
                          00
                        </span>
                      ))}
                </div>
              </td>

              {/* ASCII */}
              <td className="w-40 px-2 py-0.5 text-accent-green">
                {row.map((byte) =>
                  byte >= 0x20 && byte <= 0x7e
                    ? String.fromCharCode(byte)
                    : "."
                ).join("")}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
