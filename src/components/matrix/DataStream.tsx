import { useState, useEffect, useRef } from "react";

interface DataStreamProps {
  className?: string;
  color?: string;
  speed?: number;
  density?: number;
}

/**
 * Matrix-style falling data stream effect.
 * Creates a visual representation of flowing binary/hex data.
 */
export function DataStream({
  className = "",
  color = "green",
  speed = 50,
  density = 0.03,
}: DataStreamProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 });

  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      const canvas = canvasRef.current;
      if (canvas?.parentElement) {
        setDimensions({
          width: canvas.parentElement.clientWidth,
          height: canvas.parentElement.clientHeight,
        });
      }
    };

    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    return () => window.removeEventListener("resize", updateDimensions);
  }, []);

  // Render the falling characters
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || dimensions.width === 0) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const chars = "0123456789ABCDEF".split("");
    const fontSize = 10;
    const columns = Math.floor(dimensions.width / fontSize);
    const drops: number[] = Array(columns).fill(1);

    // Color mapping
    const colorMap: Record<string, { r: number; g: number; b: number }> = {
      green: { r: 0, g: 255, b: 0 },
      cyan: { r: 0, g: 255, b: 255 },
      purple: { r: 168, g: 85, b: 247 },
      red: { r: 255, g: 0, b: 0 },
      yellow: { r: 255, g: 255, b: 0 },
      blue: { r: 59, g: 130, b: 246 },
    };

    const rgb = colorMap[color] || colorMap.green;

    const draw = () => {
      // Semi-transparent black to create trail effect
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
      ctx.fillRect(0, 0, dimensions.width, dimensions.height);

      ctx.font = `${fontSize}px monospace`;

      for (let i = 0; i < drops.length; i++) {
        // Random character
        const char = chars[Math.floor(Math.random() * chars.length)];

        // Varying opacity based on position
        const opacity = Math.random() * 0.5 + 0.5;
        ctx.fillStyle = `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${opacity})`;

        // Draw the character
        const x = i * fontSize;
        const y = drops[i] * fontSize;
        ctx.fillText(char, x, y);

        // Reset drop to top with random chance
        if (y > dimensions.height && Math.random() > 1 - density) {
          drops[i] = 0;
        }

        drops[i]++;
      }
    };

    const interval = setInterval(draw, speed);
    return () => clearInterval(interval);
  }, [dimensions, color, speed, density]);

  return (
    <canvas
      ref={canvasRef}
      width={dimensions.width}
      height={dimensions.height}
      className={`absolute inset-0 pointer-events-none opacity-30 ${className}`}
    />
  );
}

/**
 * Live hex data visualization that scrolls.
 */
export function HexDataFlow({
  data,
  className = "",
}: {
  data?: number[];
  className?: string;
}) {
  const [displayData, setDisplayData] = useState<number[][]>([]);

  useEffect(() => {
    if (data && data.length > 0) {
      // Split data into rows of 16 bytes
      const rows: number[][] = [];
      for (let i = 0; i < data.length; i += 16) {
        rows.push(data.slice(i, i + 16));
      }
      setDisplayData(rows);
    } else {
      // Generate random data for demo
      const randomData: number[][] = [];
      for (let i = 0; i < 20; i++) {
        randomData.push(
          Array.from({ length: 16 }, () => Math.floor(Math.random() * 256))
        );
      }
      setDisplayData(randomData);
    }
  }, [data]);

  return (
    <div className={`font-mono text-[10px] overflow-hidden ${className}`}>
      {displayData.map((row, rowIdx) => (
        <div
          key={rowIdx}
          className="flex gap-1 animate-pulse"
          style={{ animationDelay: `${rowIdx * 0.1}s` }}
        >
          <span className="text-cyan-600 w-16">
            {(rowIdx * 16).toString(16).padStart(8, "0")}
          </span>
          <span className="flex gap-1">
            {row.map((byte, byteIdx) => (
              <span
                key={byteIdx}
                className={`${
                  byte === 0
                    ? "text-white/20"
                    : byte > 0x7f
                    ? "text-red-400"
                    : byte >= 0x20 && byte <= 0x7e
                    ? "text-green-400"
                    : "text-cyan-400"
                }`}
              >
                {byte.toString(16).padStart(2, "0")}
              </span>
            ))}
          </span>
        </div>
      ))}
    </div>
  );
}

/**
 * Animated connection lines between elements.
 */
export function ConnectionLines({
  connections,
}: {
  connections: { from: { x: number; y: number }; to: { x: number; y: number }; color?: string }[];
}) {
  return (
    <svg className="absolute inset-0 pointer-events-none z-40">
      <defs>
        <linearGradient id="lineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="cyan" stopOpacity="0" />
          <stop offset="50%" stopColor="cyan" stopOpacity="1" />
          <stop offset="100%" stopColor="cyan" stopOpacity="0" />
        </linearGradient>
      </defs>
      {connections.map((conn, i) => (
        <g key={i}>
          {/* Glow effect */}
          <line
            x1={conn.from.x}
            y1={conn.from.y}
            x2={conn.to.x}
            y2={conn.to.y}
            stroke={conn.color || "cyan"}
            strokeWidth="3"
            opacity="0.3"
            className="animate-pulse"
          />
          {/* Main line */}
          <line
            x1={conn.from.x}
            y1={conn.from.y}
            x2={conn.to.x}
            y2={conn.to.y}
            stroke={conn.color || "cyan"}
            strokeWidth="1"
            opacity="0.8"
          />
          {/* Animated dot traveling along line */}
          <circle r="2" fill={conn.color || "cyan"}>
            <animateMotion
              dur="2s"
              repeatCount="indefinite"
              path={`M${conn.from.x},${conn.from.y} L${conn.to.x},${conn.to.y}`}
            />
          </circle>
        </g>
      ))}
    </svg>
  );
}
