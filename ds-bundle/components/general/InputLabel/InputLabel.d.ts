import * as React from 'react';

/**
 * InputLabel — from sberpcf-design-kit@1.0.0.
 */
export interface InputLabelProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<InputLabelClasses> & Partial<ClassNameMap<never>>;
  color?: "success" | "info" | "warning" | "error" | "primary" | "secondary";
  /** If `true`, the transition animation is disabled. */
  disableAnimation?: boolean;
  /** If `true`, the component is disabled. */
  disabled?: boolean;
  /** If `true`, the label is displayed in an error state. */
  error?: boolean;
  /** If `true`, the `input` of this label is focused. */
  focused?: boolean;
  /** If `dense`, will adjust vertical spacing. This is normally obtained via context from FormControl. */
  margin?: "dense";
  /** if `true`, the label will indicate that the `input` is required. */
  required?: boolean;
  /** If `true`, the label is shrunk. */
  shrink?: boolean;
  /** The size of the component. */
  size?: "small" | "normal";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The variant to use. */
  variant?: "filled" | "outlined" | "standard";
  children?: React.ReactNode;
  /** If `true`, the label should use filled classes key. */
  filled?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export declare const InputLabel: React.ComponentType<InputLabelProps>;
