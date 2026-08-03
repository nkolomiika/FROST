import * as React from 'react';

/**
 * List — from sberpcf-design-kit@1.0.0.
 * @replaces ul
 */
export interface ListProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ListClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, compact vertical padding designed for keyboard and mouse input is used for the list and list items. The prop  */
  dense?: boolean;
  /** If `true`, vertical padding is removed from the list. */
  disablePadding?: boolean;
  /** The content of the subheader, normally `ListSubheader`. */
  subheader?: React.ReactNode;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}

export declare const List: React.ComponentType<ListProps>;
