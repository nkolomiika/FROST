import * as React from "react";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { sberTheme } from "./theme";

export interface SberThemeProviderProps {
  /** The application tree to render inside the themed context. */
  children?: React.ReactNode;
}

/**
 * Root provider for the SberPCF design system.
 *
 * Wrap the entire application in this once, at the root. It installs the dark
 * SberPCF theme (palette, zero-radius geometry, Inter typography, branded
 * component overrides) and `CssBaseline`, which applies the global dark
 * background gradient and scrollbar styling. Every component in this kit must
 * be rendered inside it — without it, MUI primitives fall back to the default
 * light Material theme and none of the SberPCF branding applies.
 *
 * @example
 * <SberThemeProvider>
 *   <App />
 * </SberThemeProvider>
 */
export function SberThemeProvider({ children }: SberThemeProviderProps) {
  return (
    <ThemeProvider theme={sberTheme}>
      <CssBaseline />
      {children}
    </ThemeProvider>
  );
}
