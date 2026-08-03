import * as React from 'react';

/**
 * InputAdornment — from sberpcf-design-kit@1.0.0.
 */
export interface InputAdornmentProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<InputAdornmentClasses> & Partial<ClassNameMap<never>>;
  /** The content of the component, normally an `IconButton` or string. */
  children?: React.ReactNode;
  /** Disable pointer events on the root. This allows for the content of the adornment to focus the `input` on click. */
  disablePointerEvents?: boolean;
  /** If children is a string then disable wrapping in a Typography component. */
  disableTypography?: boolean;
  /** The position this adornment should appear relative to the `Input`. */
  position: "end" | "start";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The variant to use. Note: If you are using the `TextField` component or the `FormControl` component you do not have to s */
  variant?: "filled" | "outlined" | "standard";
  className?: string;
  style?: React.CSSProperties;
}

export declare const InputAdornment: React.ComponentType<InputAdornmentProps>;
