import * as React from 'react';

/**
 * Toolbar — from sberpcf-design-kit@1.0.0.
 */
export interface ToolbarProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The Toolbar children, usually a mixture of `IconButton`, `Button` and `Typography`. The Toolbar is a flex container, all */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ToolbarClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, disables gutter padding. */
  disableGutters?: boolean;
  /** The variant to use. */
  variant?: "dense" | "regular";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}

export declare const Toolbar: React.ComponentType<ToolbarProps>;
