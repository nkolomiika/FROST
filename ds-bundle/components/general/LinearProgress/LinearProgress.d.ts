import * as React from 'react';

/**
 * LinearProgress — from sberpcf-design-kit@1.0.0.
 */
export interface LinearProgressProps {
  /** Override or extend the styles applied to the component. */
  classes?: Partial<LinearProgressClasses>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "inherit" | "primary" | "secondary";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The value of the progress indicator for the determinate and buffer variants. Value between 0 and 100. */
  value?: number;
  /** The value for the buffer variant. Value between 0 and 100. */
  valueBuffer?: number;
  /** The variant to use. Use indeterminate or query when there is no progress value. */
  variant?: "indeterminate" | "determinate" | "buffer" | "query";
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}

export declare const LinearProgress: React.ComponentType<LinearProgressProps>;
