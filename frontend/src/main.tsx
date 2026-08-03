import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { StormRoot } from "./StormRoot";
import { initTheme } from "./storm/theme";
import "./storm/storm.css";

// Reflect the saved light/dark preference before the first paint.
initTheme();

const rootElement = document.getElementById("root");

ReactDOM.createRoot(rootElement!).render(
  <React.StrictMode>
    <BrowserRouter>
      <StormRoot />
    </BrowserRouter>
  </React.StrictMode>
);
