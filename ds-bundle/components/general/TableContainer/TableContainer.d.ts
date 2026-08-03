import * as React from 'react';

/**
 * TableContainer — from sberpcf-design-kit@1.0.0.
 */
export interface TableContainerProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the component, normally `Table`. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TableContainerClasses> & Partial<ClassNameMap<never>>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}

export declare const TableContainer: React.ComponentType<TableContainerProps>;
