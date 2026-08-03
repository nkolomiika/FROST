import * as React from 'react';

/**
 * Paper — from sberpcf-design-kit@1.0.0.
 */
export interface PaperProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<PaperClasses> & Partial<ClassNameMap<never>>;
  /** Shadow depth, corresponds to `dp` in the spec. It accepts values between 0 and 24 inclusive. */
  elevation?: number;
  /** If `true`, rounded corners are disabled. */
  square?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The variant to use. */
  variant?: "elevation" | "outlined";
  className?: string;
  style?: React.CSSProperties;
}

export declare const Paper: React.ComponentType<PaperProps>;
