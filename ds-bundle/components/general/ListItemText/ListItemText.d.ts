import * as React from 'react';

/**
 * ListItemText — from sberpcf-design-kit@1.0.0.
 */
export interface ListItemTextProps {
  /** Alias for the `primary` prop. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ListItemTextClasses>;
  /** If `true`, the children won't be wrapped by a Typography component. This can be useful to render an alternative Typograp */
  disableTypography?: boolean;
  /** If `true`, the children are indented. This should be used if there is no left avatar or left icon. */
  inset?: boolean;
  /** The main content element. */
  primary?: React.ReactNode;
  /** These props will be forwarded to the primary typography component (as long as disableTypography is not `true`). */
  primaryTypographyProps?: TypographyProps<PrimaryTypographyComponent, { component?: PrimaryTypographyComponent; }>;
  /** The secondary content element. */
  secondary?: React.ReactNode;
  /** These props will be forwarded to the secondary typography component (as long as disableTypography is not `true`). */
  secondaryTypographyProps?: TypographyProps<SecondaryTypographyComponent, { component?: SecondaryTypographyComponent; }>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
  /** The components used for each slot inside. */
  slots?: Partial<ListItemTextSlots>;
  /** The props used for each slot inside. */
  slotProps?: { root?: SlotProps<"div", {}, ListItemTextOwnerState>; primary?: SlotProps<React.ElementType<TypographyProps>, {}, ListItemTextOwnerState>; secondary?: SlotProps<React.ElementType<TypographyProps>, {}, ListItemTextOwnerState>; };
}

export declare const ListItemText: React.ComponentType<ListItemTextProps>;
