import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { FrostRoot } from "./FrostRoot";
import { initTheme } from "./frost/theme";
import "./frost/frost.css";

// Reflect the saved light/dark preference before the first paint.
initTheme();

const rootElement = document.getElementById("root");

ReactDOM.createRoot(rootElement!).render(
  <React.StrictMode>
    <BrowserRouter>
      <FrostRoot />
    </BrowserRouter>
  </React.StrictMode>
);
