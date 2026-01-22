import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { tauriApi } from "./lib/tauri";

// Expose API to window for component access
declare global {
  interface Window {
    __OTPBAR__: {
      getPrivacyData: () => Promise<import("./types/tauri").PrivacyData>;
      clearHistory: () => Promise<void>;
    };
  }
}

window.__OTPBAR__ = {
  getPrivacyData: tauriApi.getPrivacyData,
  clearHistory: tauriApi.clearHistory,
};

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
