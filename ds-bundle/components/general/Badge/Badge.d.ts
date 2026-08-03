import * as React from 'react';

/**
 * Badge — from sberpcf-design-kit@1.0.0.
 */
export interface BadgeProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The anchor of the badge. */
  anchorOrigin?: BadgeOrigin;
  /** The content rendered within the badge. */
  badgeContent?: React.ReactNode;
  /** The badge will be added relative to this node. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<BadgeClasses> & Partial<ClassNameMap<never>>;
  className?: string;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "default" | "primary" | "secondary";
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { root?: SlotProps<"span", BadgeRootSlotPropsOverrides, BadgeOwnerState>; badge?: SlotProps<"span", BadgeBadgeSlotPropsOverrides, BadgeOwnerState>; };
  /** The components used for each slot inside. */
  components?: { Root?: React.ElementType; Badge?: React.ElementType; };
  /** If `true`, the badge is invisible. */
  invisible?: boolean;
  /** Max count to show. */
  max?: number;
  /** Wrapped shape the badge should overlap. */
  overlap?: "circular" | "rectangular";
  /** Controls whether the badge is hidden when `badgeContent` is zero. */
  showZero?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The variant to use. */
  variant?: "standard" | "dot";
  /** The components used for each slot inside. */
  slots?: Partial<BadgeSlots>;
  /** The props used for each slot inside. */
  slotProps?: { root?: SlotProps<"span", BadgeRootSlotPropsOverrides, BadgeOwnerState>; badge?: SlotProps<"span", BadgeBadgeSlotPropsOverrides, BadgeOwnerState>; };
  style?: React.CSSProperties;
}

export declare const Badge: React.ComponentType<BadgeProps>;
