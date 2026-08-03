import * as React from 'react';

/**
 * DialogActions — from sberpcf-design-kit@1.0.0.
 */
export interface DialogActionsProps {
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<DialogActionsClasses>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** If `true`, the actions do not have additional margin. */
  disableSpacing?: boolean;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}

export declare const DialogActions: React.ComponentType<DialogActionsProps>;
