import { useState, useRef, useEffect, ReactNode } from "react";
import { X, Minimize2, Maximize2, Move, Eye, EyeOff } from "lucide-react";

interface FloatingPaneProps {
  id: string;
  title: string;
  children: ReactNode;
  initialPosition?: { x: number; y: number };
  initialSize?: { width: number; height: number };
  onClose?: () => void;
  className?: string;
  glowColor?: string;
  isMinimized?: boolean;
  isTransparent?: boolean;
}

export function FloatingPane({
  id,
  title,
  children,
  initialPosition = { x: 100, y: 100 },
  initialSize = { width: 400, height: 300 },
  onClose,
  className = "",
  glowColor = "cyan",
  isMinimized: initialMinimized = false,
  isTransparent: initialTransparent = false,
}: FloatingPaneProps) {
  const [position, setPosition] = useState(initialPosition);
  const [size, setSize] = useState(initialSize);
  const [isDragging, setIsDragging] = useState(false);
  const [isResizing, setIsResizing] = useState(false);
  const [isMinimized, setIsMinimized] = useState(initialMinimized);
  const [isTransparent, setIsTransparent] = useState(initialTransparent);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const paneRef = useRef<HTMLDivElement>(null);

  // Handle dragging
  const handleMouseDown = (e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".pane-controls")) return;
    setIsDragging(true);
    setDragOffset({
      x: e.clientX - position.x,
      y: e.clientY - position.y,
    });
  };

  const handleResizeStart = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsResizing(true);
    setDragOffset({
      x: e.clientX,
      y: e.clientY,
    });
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (isDragging) {
        setPosition({
          x: e.clientX - dragOffset.x,
          y: e.clientY - dragOffset.y,
        });
      }
      if (isResizing) {
        const deltaX = e.clientX - dragOffset.x;
        const deltaY = e.clientY - dragOffset.y;
        setSize({
          width: Math.max(200, size.width + deltaX),
          height: Math.max(100, size.height + deltaY),
        });
        setDragOffset({ x: e.clientX, y: e.clientY });
      }
    };

    const handleMouseUp = () => {
      setIsDragging(false);
      setIsResizing(false);
    };

    if (isDragging || isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isDragging, isResizing, dragOffset, size]);

  const glowStyles: Record<string, string> = {
    cyan: "shadow-[0_0_15px_rgba(0,255,255,0.3),0_0_30px_rgba(0,255,255,0.1)] border-cyan-500/50",
    green: "shadow-[0_0_15px_rgba(0,255,0,0.3),0_0_30px_rgba(0,255,0,0.1)] border-green-500/50",
    purple: "shadow-[0_0_15px_rgba(168,85,247,0.3),0_0_30px_rgba(168,85,247,0.1)] border-purple-500/50",
    red: "shadow-[0_0_15px_rgba(255,0,0,0.3),0_0_30px_rgba(255,0,0,0.1)] border-red-500/50",
    yellow: "shadow-[0_0_15px_rgba(255,255,0,0.3),0_0_30px_rgba(255,255,0,0.1)] border-yellow-500/50",
    blue: "shadow-[0_0_15px_rgba(59,130,246,0.3),0_0_30px_rgba(59,130,246,0.1)] border-blue-500/50",
  };

  const textColors: Record<string, string> = {
    cyan: "text-cyan-400",
    green: "text-green-400",
    purple: "text-purple-400",
    red: "text-red-400",
    yellow: "text-yellow-400",
    blue: "text-blue-400",
  };

  return (
    <div
      ref={paneRef}
      className={`fixed z-50 rounded-lg border ${
        isTransparent ? "bg-black/60 backdrop-blur-sm" : "bg-bg-secondary/95 backdrop-blur-md"
      } ${glowStyles[glowColor] || glowStyles.cyan} ${className} transition-all duration-200`}
      style={{
        left: position.x,
        top: position.y,
        width: size.width,
        height: isMinimized ? 36 : size.height,
      }}
    >
      {/* Header */}
      <div
        className={`h-9 flex items-center justify-between px-3 cursor-move border-b border-white/10 ${
          isMinimized ? "rounded-lg" : "rounded-t-lg"
        } bg-black/40`}
        onMouseDown={handleMouseDown}
      >
        <div className={`flex items-center gap-2 text-xs font-bold tracking-wider ${textColors[glowColor]}`}>
          <Move className="w-3 h-3 opacity-50" />
          <span className="uppercase">{title}</span>
        </div>
        <div className="pane-controls flex items-center gap-1">
          <button
            onClick={() => setIsTransparent(!isTransparent)}
            className="p-1 hover:bg-white/10 rounded transition-colors"
            title={isTransparent ? "Make opaque" : "Make transparent"}
          >
            {isTransparent ? (
              <Eye className="w-3 h-3 text-white/50" />
            ) : (
              <EyeOff className="w-3 h-3 text-white/50" />
            )}
          </button>
          <button
            onClick={() => setIsMinimized(!isMinimized)}
            className="p-1 hover:bg-white/10 rounded transition-colors"
          >
            {isMinimized ? (
              <Maximize2 className="w-3 h-3 text-white/50" />
            ) : (
              <Minimize2 className="w-3 h-3 text-white/50" />
            )}
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="p-1 hover:bg-red-500/20 rounded transition-colors"
            >
              <X className="w-3 h-3 text-red-400" />
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      {!isMinimized && (
        <div className="overflow-auto" style={{ height: size.height - 36 }}>
          {children}
        </div>
      )}

      {/* Resize Handle */}
      {!isMinimized && (
        <div
          className="absolute bottom-0 right-0 w-4 h-4 cursor-se-resize"
          onMouseDown={handleResizeStart}
        >
          <svg
            className="w-4 h-4 text-white/30"
            viewBox="0 0 24 24"
            fill="currentColor"
          >
            <path d="M22 22H20V20H22V22ZM22 18H18V22H22V18ZM14 22H18V18H14V22Z" />
          </svg>
        </div>
      )}
    </div>
  );
}
