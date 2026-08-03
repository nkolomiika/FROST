import * as React from 'react';

/**
 * Container — from sberpcf-design-kit@1.0.0.
 */
export interface ContainerProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ContainerClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, the left and right padding is removed. */
  disableGutters?: boolean;
  /** Set the max-width to match the min-width of the current breakpoint. This is useful if you'd prefer to design for a fixed */
  fixed?: boolean;
  /** Determine the max-width of the container. The container width grows with the size of the screen. Set to `false` to disab */
  maxWidth?: false | "xs" | "sm" | "md" | "lg" | "xl";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}

export declare const Container: React.ComponentType<ContainerProps>;
