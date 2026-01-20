import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', "Menlo", "Monaco", "Consolas", '"Liberation Mono"', '"Courier New"', "monospace"],
      },
      colors: {
        terminal: {
          bg: "#0c0c0c",
          fg: "#cccccc",
          accent: "#4af626", // Matrix green-ish / terminal green
          dim: "#666666",
          border: "#333333",
          selection: "#1c1c1c",
        }
      }
    },
  },
  plugins: [],
} satisfies Config;
