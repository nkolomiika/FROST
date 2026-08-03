import * as React from 'react';

/**
 * CardContent — from sberpcf-design-kit@1.0.0.
 */
export interface CardContentProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<CardContentClasses> & Partial<ClassNameMap<never>>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}

export declare const CardContent: React.ComponentType<CardContentProps>;
