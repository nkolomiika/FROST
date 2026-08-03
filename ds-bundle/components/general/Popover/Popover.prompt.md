Popover from sberpcf-design-kit. Use via `window.SberDesignKit.Popover` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface PopoverProps {
  /** A ref for imperative actions. It currently only supports updatePosition() action. */
  action?: React.Ref;
  /** An HTML element, [PopoverVirtualElement](https://mui.com/material-ui/react-popover/#virtual-element), or a function that */
  anchorEl?: Element | PopoverVirtualElement | (() => Element | PopoverVirtualElement | null);
  /** This is the point on the anchor where the popover's `anchorEl` will attach to. This is not used when the anchorReference */
  anchorOrigin?: PopoverOrigin;
  /** This is the position that may be used to set the position of the popover. The coordinates are relative to the applicatio */
  anchorPosition?: PopoverPosition;
  /** This determines which anchor prop to refer to when setting the position of the popover. */
  anchorReference?: "none" | "anchorEl" | "anchorPosition";
  /** A backdrop component. This prop enables custom backdrop rendering. */
  BackdropComponent?: React.ComponentClass<BackdropProps, any> | React.FunctionComponent<BackdropProps>;
  /** Props applied to the [`Backdrop`](/material-ui/api/backdrop/) element. */
  BackdropProps?: Partial<BackdropProps>;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<PopoverClasses>;
  /** An HTML element, component instance, or function that returns either. The `container` will passed to the Modal component */
  container?: Element | (() => Element | null);
  /** The elevation of the popover. */
  elevation?: number;
  /** Specifies how close to the edge of the window the popover can appear. If null, the popover will not be constrained by th */
  marginThreshold?: number;
  /** If `true`, the component is shown. */
  open: boolean;
  /** Props applied to the [`Paper`](https://mui.com/material-ui/api/paper/) element. This prop is an alias for `slotProps.pap */
  PaperProps?: Partial<PaperProps<React.ElementType<any, keyof React.JSX.IntrinsicElements>>>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** This is the point on the popover which will attach to the anchor's origin. Options: vertical: [top, center, bottom, x(px */
  transformOrigin?: PopoverOrigin;
  /** The component used for the transition. [Follow this guide](https://mui.com/material-ui/transitions/#transitioncomponent- */
  TransitionComponent?: unknown;
  /** Set to 'auto' to automatically calculate transition time based on height. */
  transitionDuration?: number | "auto" | { appear?: number | undefined; enter?: number | undefined; exit?: number | undefined; };
  /** Props applied to the transition element. By default, the element is based on this [`Transition`](https://reactcommunity. */
  TransitionProps?: TransitionProps;
  className?: string;
  style?: React.CSSProperties;
  ref?: React.Ref;
  id?: string;
  component?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** The `children` will be under the DOM hierarchy of the parent component. */
  disablePortal?: boolean;
  /** Always keep the children in the DOM. This prop can be useful in SEO situation or when you want to maximize the responsiv */
  keepMounted?: boolean;
  /** The components used for each slot inside. */
  components?: { Root?: React.ElementType; Backdrop?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { root?: SlotComponentProps<"div", ModalComponentsPropsOverrides, ModalOwnerState>; backdrop?: SlotComponentProps<OverridableComponent<BackdropTypeMap<{}, "div">>, ModalComponentsPropsOverrides, ModalOwnerState>; };
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
  /** The components used for each slot inside. */
  slots?: Partial<PopoverSlots>;
  /** The props used for each slot inside. */
  slotProps?: unknown;
}
```
