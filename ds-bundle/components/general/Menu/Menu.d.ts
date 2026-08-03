import * as React from 'react';

/**
 * Menu — from sberpcf-design-kit@1.0.0.
 */
export interface MenuProps {
  /** An HTML element, or a function that returns one. It's used to set the position of the menu. */
  anchorEl?: Element | PopoverVirtualElement | (() => Element | PopoverVirtualElement | null);
  /** If `true` (Default) will focus the `[role="menu"]` if no focusable child is found. Disabled children are not focusable.  */
  autoFocus?: boolean;
  /** Menu contents, normally `MenuItem`s. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<MenuClasses>;
  /** When opening the menu will not focus the active item but the `[role="menu"]` unless `autoFocus` is also set to `false`.  */
  disableAutoFocusItem?: boolean;
  /** Props applied to the [`MenuList`](https://mui.com/material-ui/api/menu-list/) element. */
  MenuListProps?: Partial<MenuListProps>;
  /** If `true`, the component is shown. */
  open: boolean;
  /** `classes` prop applied to the [`Popover`](https://mui.com/material-ui/api/popover/) element. */
  PopoverClasses?: Partial<PopoverClasses>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The length of the transition in `ms`, or 'auto' */
  transitionDuration?: number | "auto" | { appear?: number | undefined; enter?: number | undefined; exit?: number | undefined; };
  /** Props applied to the transition element. By default, the element is based on this [`Transition`](https://reactcommunity. */
  TransitionProps?: TransitionProps;
  /** The variant to use. Use `menu` to prevent selected items from impacting the initial focus. */
  variant?: "menu" | "selectedMenu";
  className?: string;
  style?: React.CSSProperties;
  /** The elevation of the popover. */
  elevation?: number;
  ref?: React.Ref;
  id?: string;
  component?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** A ref for imperative actions. It currently only supports updatePosition() action. */
  action?: React.Ref;
  /** This is the point on the popover which will attach to the anchor's origin. Options: vertical: [top, center, bottom, x(px */
  transformOrigin?: PopoverOrigin;
  /** An HTML element, component instance, or function that returns either. The `container` will passed to the Modal component */
  container?: Element | (() => Element | null);
  /** The `children` will be under the DOM hierarchy of the parent component. */
  disablePortal?: boolean;
  /** Always keep the children in the DOM. This prop can be useful in SEO situation or when you want to maximize the responsiv */
  keepMounted?: boolean;
  /** The components used for each slot inside. */
  components?: { Root?: React.ElementType; Backdrop?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { root?: SlotComponentProps<"div", ModalComponentsPropsOverrides, ModalOwnerState>; backdrop?: SlotComponentProps<OverridableComponent<BackdropTypeMap<{}, "div">>, ModalComponentsPropsOverrides, ModalOwnerState>; };
  /** This is the point on the anchor where the popover's `anchorEl` will attach to. This is not used when the anchorReference */
  anchorOrigin?: PopoverOrigin;
  /** A backdrop component. This prop enables custom backdrop rendering. */
  BackdropComponent?: React.ComponentClass<BackdropProps, any> | React.FunctionComponent<BackdropProps>;
  /** Props applied to the [`Backdrop`](/material-ui/api/backdrop/) element. */
  BackdropProps?: Partial<BackdropProps>;
  /** When set to true the Modal waits until a nested Transition is completed before closing. */
  closeAfterTransition?: boolean;
  /** If `true`, the modal will not automatically shift focus to itself when it opens, and replace it to the last focused elem */
  disableAutoFocus?: boolean;
  /** If `true`, the modal will not prevent focus from leaving the modal while open. Generally this should never be set to `tr */
  disableEnforceFocus?: boolean;
  /** If `true`, hitting escape will not fire the `onClose` callback. */
  disableEscapeKeyDown?: boolean;
  /** If `true`, the modal will not restore focus to previously focused element once modal is hidden or unmounted. */
  disableRestoreFocus?: boolean;
  /** Disable the scroll lock behavior. */
  disableScrollLock?: boolean;
  /** If `true`, the backdrop is not rendered. */
  hideBackdrop?: boolean;
  /** The component used for the transition. [Follow this guide](https://mui.com/material-ui/transitions/#transitioncomponent- */
  TransitionComponent?: unknown;
  /** This is the position that may be used to set the position of the popover. The coordinates are relative to the applicatio */
  anchorPosition?: PopoverPosition;
  /** This determines which anchor prop to refer to when setting the position of the popover. */
  anchorReference?: "none" | "anchorEl" | "anchorPosition";
  /** Specifies how close to the edge of the window the popover can appear. If null, the popover will not be constrained by th */
  marginThreshold?: number;
  /** Props applied to the [`Paper`](https://mui.com/material-ui/api/paper/) element. This prop is an alias for `slotProps.pap */
  PaperProps?: Partial<PaperProps<React.ElementType<any, keyof React.JSX.IntrinsicElements>>>;
  /** The components used for each slot inside. */
  slots?: Partial<MenuSlots>;
  /** The props used for each slot inside. */
  slotProps?: unknown;
}

export declare const Menu: React.ComponentType<MenuProps>;
