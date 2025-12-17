import { useState, useMemo } from "react";
import { useAnalysisStore } from "../../stores/analysisStore";
import {
  Search, Copy, Check, FileSearch, Link2,
  Globe, Key, FolderOpen, FileText, AlertTriangle,
  ChevronDown, ChevronRight, ExternalLink
} from "lucide-react";

type StringCategory = "all" | "urls" | "ips" | "registry" | "paths" | "suspicious" | "api" | "other";

interface CategorizedString {
  offset: string;
  value: string;
  length: number;
  category: StringCategory;
  xrefs: string[];
}

// Suspicious API names
const SUSPICIOUS_APIS = [
  "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
  "CreateRemoteThread", "NtUnmapViewOfSection", "NtWriteVirtualMemory",
  "LoadLibrary", "GetProcAddress", "GetModuleHandle",
  "RegCreateKey", "RegSetValue", "RegOpenKey",
  "WinExec", "ShellExecute", "CreateProcess", "system",
  "InternetOpen", "InternetConnect", "HttpSendRequest",
  "WSAStartup", "socket", "connect", "send", "recv",
  "OpenProcess", "TerminateProcess", "SuspendThread",
  "SetWindowsHook", "GetAsyncKeyState", "GetKeyState",
  "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
];

export function StringsView() {
  const { result, navigateTo, getXrefsFrom } = useAnalysisStore();
  const [filter, setFilter] = useState("");
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<StringCategory>("all");
  const [expandedXrefs, setExpandedXrefs] = useState<Set<number>>(new Set());
  const [sortBy, setSortBy] = useState<"offset" | "length" | "value">("offset");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const strings = result?.strings || [];

  // Categorize strings
  const categorizedStrings = useMemo((): CategorizedString[] => {
    return strings.map((str) => {
      const lower = str.value.toLowerCase();
      let category: StringCategory = "other";

      // URLs
      if (/https?:\/\/|ftp:\/\/|file:\/\//i.test(str.value)) {
        category = "urls";
      }
      // IPs
      else if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(str.value)) {
        category = "ips";
      }
      // Registry
      else if (/HKEY_|\\Software\\|\\CurrentVersion|\\Run/i.test(str.value)) {
        category = "registry";
      }
      // Paths
      else if (/[A-Za-z]:\\|\\\\[\w.]+\\|\/usr\/|\/etc\//i.test(str.value)) {
        category = "paths";
      }
      // Suspicious APIs
      else if (SUSPICIOUS_APIS.some((api) => lower.includes(api.toLowerCase()))) {
        category = "api";
      }
      // Suspicious keywords
      else if (
        /(password|secret|credential|token|admin|root|cmd\.exe|powershell|encrypt|decrypt|ransom)/i.test(
          lower
        )
      ) {
        category = "suspicious";
      }

      // Find xrefs to this string offset
      const xrefs = getXrefsFrom(str.offset);

      return {
        ...str,
        category,
        xrefs: xrefs.map((x) => x.to),
      };
    });
  }, [strings, getXrefsFrom]);

  // Filter and sort strings
  const filteredStrings = useMemo(() => {
    let filtered = categorizedStrings;

    // Category filter
    if (selectedCategory !== "all") {
      filtered = filtered.filter((s) => s.category === selectedCategory);
    }

    // Text filter
    if (filter) {
      const lowerFilter = filter.toLowerCase();
      filtered = filtered.filter(
        (s) =>
          s.value.toLowerCase().includes(lowerFilter) ||
          s.offset.toLowerCase().includes(lowerFilter)
      );
    }

    // Sort
    filtered = [...filtered].sort((a, b) => {
      let cmp = 0;
      switch (sortBy) {
        case "offset":
          cmp = a.offset.localeCompare(b.offset);
          break;
        case "length":
          cmp = a.length - b.length;
          break;
        case "value":
          cmp = a.value.localeCompare(b.value);
          break;
      }
      return sortDir === "asc" ? cmp : -cmp;
    });

    return filtered;
  }, [categorizedStrings, selectedCategory, filter, sortBy, sortDir]);

  // Category counts
  const categoryCounts = useMemo(() => {
    const counts: Record<StringCategory, number> = {
      all: categorizedStrings.length,
      urls: 0,
      ips: 0,
      registry: 0,
      paths: 0,
      suspicious: 0,
      api: 0,
      other: 0,
    };

    categorizedStrings.forEach((s) => {
      counts[s.category]++;
    });

    return counts;
  }, [categorizedStrings]);

  const copyToClipboard = async (value: string, idx: number) => {
    await navigator.clipboard.writeText(value);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  };

  const toggleXrefs = (idx: number) => {
    const newExpanded = new Set(expandedXrefs);
    if (newExpanded.has(idx)) {
      newExpanded.delete(idx);
    } else {
      newExpanded.add(idx);
    }
    setExpandedXrefs(newExpanded);
  };

  const handleSort = (col: "offset" | "length" | "value") => {
    if (sortBy === col) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortBy(col);
      setSortDir("asc");
    }
  };

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center text-text-secondary">
        <div className="text-center">
          <FileSearch className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p>No strings to display</p>
          <p className="text-xs mt-1">Analyze a file to extract strings</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Search and Category Bar */}
      <div className="bg-bg-secondary border-b border-border">
        {/* Search */}
        <div className="h-10 flex items-center px-3 gap-2 border-b border-border">
          <Search className="w-4 h-4 text-text-secondary" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter strings..."
            className="flex-1 bg-transparent text-sm focus:outline-none"
          />
          <span className="text-xs text-text-secondary">
            {filteredStrings.length} / {strings.length}
          </span>
        </div>

        {/* Category Filters */}
        <div className="h-8 flex items-center px-2 gap-1 overflow-x-auto">
          {[
            { id: "all", label: "All", icon: FileText },
            { id: "urls", label: "URLs", icon: Globe },
            { id: "ips", label: "IPs", icon: Globe },
            { id: "registry", label: "Registry", icon: Key },
            { id: "paths", label: "Paths", icon: FolderOpen },
            { id: "api", label: "APIs", icon: Link2 },
            { id: "suspicious", label: "Suspicious", icon: AlertTriangle },
          ].map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setSelectedCategory(id as StringCategory)}
              className={`flex items-center gap-1 px-2 py-0.5 text-xs rounded transition-colors ${
                selectedCategory === id
                  ? "bg-accent-blue/20 text-accent-blue"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
              }`}
            >
              <Icon className="w-3 h-3" />
              {label}
              {categoryCounts[id as StringCategory] > 0 && (
                <span className="ml-1 px-1 py-0.5 text-[10px] bg-bg-tertiary rounded">
                  {categoryCounts[id as StringCategory]}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Strings list */}
      <div className="flex-1 overflow-auto font-mono text-sm">
        <table className="w-full">
          <thead className="sticky top-0 bg-bg-secondary z-10">
            <tr className="text-text-secondary text-xs">
              <th className="w-6 px-1 py-1"></th>
              <th
                className="w-20 px-3 py-1 text-left cursor-pointer hover:text-text-primary"
                onClick={() => handleSort("offset")}
              >
                Offset {sortBy === "offset" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th className="w-8 px-1 py-1 text-center text-[10px]">Xrefs</th>
              <th
                className="w-12 px-2 py-1 text-right cursor-pointer hover:text-text-primary"
                onClick={() => handleSort("length")}
              >
                Len {sortBy === "length" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th
                className="px-3 py-1 text-left cursor-pointer hover:text-text-primary"
                onClick={() => handleSort("value")}
              >
                Value {sortBy === "value" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th className="w-8 px-1 py-1"></th>
            </tr>
          </thead>
          <tbody>
            {filteredStrings.map((str, idx) => (
              <>
                <tr
                  key={idx}
                  className="hover:bg-bg-hover border-b border-border/30 cursor-pointer"
                  onClick={() => navigateTo(str.offset)}
                >
                  {/* Expand xrefs button */}
                  <td className="w-6 px-1 py-1 text-center">
                    {str.xrefs.length > 0 && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleXrefs(idx);
                        }}
                        className="p-0.5 hover:bg-bg-tertiary rounded"
                      >
                        {expandedXrefs.has(idx) ? (
                          <ChevronDown className="w-3 h-3" />
                        ) : (
                          <ChevronRight className="w-3 h-3" />
                        )}
                      </button>
                    )}
                  </td>

                  {/* Offset */}
                  <td className="w-20 px-3 py-1 text-accent-blue">
                    {str.offset}
                  </td>

                  {/* Xrefs count */}
                  <td className="w-8 px-1 py-1 text-center">
                    {str.xrefs.length > 0 && (
                      <span className="text-[10px] px-1 py-0.5 bg-bg-tertiary rounded text-accent-purple">
                        {str.xrefs.length}
                      </span>
                    )}
                  </td>

                  {/* Length */}
                  <td className="w-12 px-2 py-1 text-right text-text-secondary text-xs">
                    {str.length}
                  </td>

                  {/* Value */}
                  <td className="px-3 py-1">
                    <span className={getCategoryStyle(str.category)}>
                      {formatString(str.value)}
                    </span>
                    {str.category !== "other" && (
                      <span className="ml-2 px-1 py-0.5 text-[9px] bg-bg-tertiary rounded uppercase">
                        {str.category}
                      </span>
                    )}
                  </td>

                  {/* Copy button */}
                  <td className="w-8 px-1 py-1">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        copyToClipboard(str.value, idx);
                      }}
                      className="p-1 hover:bg-bg-hover rounded transition-colors"
                      title="Copy to clipboard"
                    >
                      {copiedIdx === idx ? (
                        <Check className="w-3 h-3 text-accent-green" />
                      ) : (
                        <Copy className="w-3 h-3 text-text-secondary" />
                      )}
                    </button>
                  </td>
                </tr>

                {/* Expanded xrefs */}
                {expandedXrefs.has(idx) && str.xrefs.length > 0 && (
                  <tr key={`xrefs-${idx}`} className="bg-bg-tertiary/50">
                    <td colSpan={6} className="px-6 py-2">
                      <div className="text-xs text-text-secondary">
                        <span className="font-semibold">Referenced from:</span>
                        <div className="flex flex-wrap gap-2 mt-1">
                          {str.xrefs.map((xref, xidx) => (
                            <button
                              key={xidx}
                              onClick={() => navigateTo(xref)}
                              className="flex items-center gap-1 px-2 py-0.5 bg-bg-primary hover:bg-bg-hover rounded text-accent-blue"
                            >
                              <ExternalLink className="w-3 h-3" />
                              {xref}
                            </button>
                          ))}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>

        {filteredStrings.length === 0 && (
          <div className="py-8 text-center text-text-secondary text-sm">
            No strings match the filter
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="h-5 bg-bg-secondary border-t border-border flex items-center justify-between px-3 text-[10px] text-text-secondary shrink-0">
        <span>
          {filteredStrings.length} strings shown
          {selectedCategory !== "all" && ` (${selectedCategory})`}
        </span>
        <span>
          {categoryCounts.suspicious > 0 && (
            <span className="text-accent-red mr-3">
              {categoryCounts.suspicious} suspicious
            </span>
          )}
          {categoryCounts.urls > 0 && (
            <span className="text-accent-orange mr-3">
              {categoryCounts.urls} URLs
            </span>
          )}
          {categoryCounts.ips > 0 && (
            <span className="text-accent-yellow">
              {categoryCounts.ips} IPs
            </span>
          )}
        </span>
      </div>
    </div>
  );
}

// Get color based on category
function getCategoryStyle(category: StringCategory): string {
  switch (category) {
    case "urls":
      return "text-accent-red";
    case "ips":
      return "text-accent-orange";
    case "registry":
      return "text-accent-yellow";
    case "paths":
      return "text-accent-cyan";
    case "api":
      return "text-accent-purple";
    case "suspicious":
      return "text-accent-red font-semibold";
    default:
      return "text-text-primary";
  }
}

// Format string for display (escape special chars, truncate)
function formatString(value: string): string {
  // Escape control characters
  let formatted = value
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t")
    .replace(/\0/g, "\\0");

  // Truncate long strings
  if (formatted.length > 80) {
    formatted = formatted.substring(0, 80) + "...";
  }

  return formatted;
}
