import * as React from 'react';

/**
 * DialogContent — from sberpcf-design-kit@1.0.0.
 */
export interface DialogContentProps {
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<DialogContentClasses>;
  /** Display the top and bottom dividers. */
  dividers?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}

export declare const DialogContent: React.ComponentType<DialogContentProps>;
