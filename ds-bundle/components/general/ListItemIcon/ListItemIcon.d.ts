import * as React from 'react';

/**
 * ListItemIcon — from sberpcf-design-kit@1.0.0.
 */
export interface ListItemIconProps {
  /** The content of the component, normally `Icon`, `SvgIcon`, or a `@mui/icons-material` SVG icon element. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ListItemIconClasses>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}

export declare const ListItemIcon: React.ComponentType<ListItemIconProps>;
