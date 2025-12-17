/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Dark theme colors for debugger UI
        bg: {
          primary: "#1e1e1e",
          secondary: "#252526",
          tertiary: "#2d2d2d",
          hover: "#3c3c3c",
        },
        text: {
          primary: "#cccccc",
          secondary: "#858585",
          accent: "#569cd6",
        },
        accent: {
          blue: "#569cd6",
          green: "#4ec9b0",
          yellow: "#dcdcaa",
          orange: "#ce9178",
          red: "#f44747",
          purple: "#c586c0",
        },
        border: "#3c3c3c",
      },
      fontFamily: {
        mono: ["Consolas", "Monaco", "Courier New", "monospace"],
      },
    },
  },
  plugins: [],
}
