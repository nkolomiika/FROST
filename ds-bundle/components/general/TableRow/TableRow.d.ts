import * as React from 'react';

/**
 * TableRow — from sberpcf-design-kit@1.0.0.
 */
export interface TableRowProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Should be valid `<tr>` children such as `TableCell`. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TableRowClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, the table row will shade on hover. */
  hover?: boolean;
  /** If `true`, the table row will have the selected shading. */
  selected?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}

export declare const TableRow: React.ComponentType<TableRowProps>;
