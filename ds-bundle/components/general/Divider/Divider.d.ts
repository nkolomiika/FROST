import * as React from 'react';

/**
 * Divider — from sberpcf-design-kit@1.0.0.
 */
export interface DividerProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Absolutely position the element. */
  absolute?: boolean;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<DividerClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, a vertical divider will have the correct height when used in flex container. (By default, a vertical divider  */
  flexItem?: boolean;
  /** If `true`, the divider will have a lighter color. */
  light?: boolean;
  /** The component orientation. */
  orientation?: "horizontal" | "vertical";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The text alignment. */
  textAlign?: "center" | "left" | "right";
  /** The variant to use. */
  variant?: "inset" | "middle" | "fullWidth";
  className?: string;
  style?: React.CSSProperties;
}

export declare const Divider: React.ComponentType<DividerProps>;
