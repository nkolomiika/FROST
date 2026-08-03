import * as React from 'react';

/**
 * Card — from sberpcf-design-kit@1.0.0.
 */
export interface CardProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<CardClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, the card will use raised styling. */
  raised?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Shadow depth, corresponds to `dp` in the spec. It accepts values between 0 and 24 inclusive. */
  elevation?: number;
  /** If `true`, rounded corners are disabled. */
  square?: boolean;
  /** The variant to use. */
  variant?: "elevation" | "outlined";
  className?: string;
  style?: React.CSSProperties;
}

export declare const Card: React.ComponentType<CardProps>;
