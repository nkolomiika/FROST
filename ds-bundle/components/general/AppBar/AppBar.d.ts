import * as React from 'react';

/**
 * AppBar — from sberpcf-design-kit@1.0.0.
 */
export interface AppBarProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<AppBarClasses> & Partial<ClassNameMap<never>>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "inherit" | "default" | "primary" | "secondary" | "transparent";
  /** If true, the `color` prop is applied in dark mode. */
  enableColorOnDark?: boolean;
  /** The positioning type. The behavior of the different options is described [in the MDN web docs](https://developer.mozilla */
  position?: "fixed" | "absolute" | "sticky" | "static" | "relative";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Shadow depth, corresponds to `dp` in the spec. It accepts values between 0 and 24 inclusive. */
  elevation?: number;
  /** If `true`, rounded corners are disabled. */
  square?: boolean;
  /** The variant to use. */
  variant?: "elevation" | "outlined";
  className?: string;
  style?: React.CSSProperties;
}

export declare const AppBar: React.ComponentType<AppBarProps>;
