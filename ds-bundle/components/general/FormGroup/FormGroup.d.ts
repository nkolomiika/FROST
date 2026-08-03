import * as React from 'react';

/**
 * FormGroup — from sberpcf-design-kit@1.0.0.
 */
export interface FormGroupProps {
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<FormGroupClasses>;
  /** Display group of elements in a compact row. */
  row?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}

export declare const FormGroup: React.ComponentType<FormGroupProps>;
