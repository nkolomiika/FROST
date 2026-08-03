Dialog from sberpcf-design-kit. Use via `window.SberDesignKit.Dialog` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface DialogProps {
  /** Dialog children, usually the included sub-components. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<DialogClasses>;
  /** If `true`, hitting escape will not fire the `onClose` callback. */
  disableEscapeKeyDown?: boolean;
  /** If `true`, the dialog is full-screen. */
  fullScreen?: boolean;
  /** If `true`, the dialog stretches to `maxWidth`. Notice that the dialog width grow is limited by the default margin. */
  fullWidth?: boolean;
  /** Determine the max-width of the dialog. The dialog width grows with the size of the screen. Set to `false` to disable `ma */
  maxWidth?: false | "xs" | "sm" | "md" | "lg" | "xl";
  /** If `true`, the component is shown. */
  open: boolean;
  /** The component used to render the body of the dialog. */
  PaperComponent?: ((props: PaperProps, deprecatedLegacyContext?: any) => React.ReactNode) | (new (props: PaperProps, deprecatedLegacyContext?: any) => React.Component<any, any>);
  /** Props applied to the [`Paper`](https://mui.com/material-ui/api/paper/) element. */
  PaperProps?: Partial<PaperProps<React.ElementType<any, keyof React.JSX.IntrinsicElements>>>;
  /** Determine the container for scrolling the dialog. */
  scroll?: "body" | "paper";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The component used for the transition. [Follow this guide](https://mui.com/material-ui/transitions/#transitioncomponent- */
  TransitionComponent?: unknown;
  /** The duration for the transition, in milliseconds. You may specify a single timeout for all transitions, or individually  */
  transitionDuration?: number | { appear?: number | undefined; enter?: number | undefined; exit?: number | undefined; };
  /** Props applied to the transition element. By default, the element is based on this [`Transition`](https://reactcommunity. */
  TransitionProps?: TransitionProps;
  className?: string;
  style?: React.CSSProperties;
  ref?: React.Ref;
  id?: string;
  component?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** An HTML element or function that returns one. The `container` will have the portal children appended to it. You can also */
  container?: Element | (() => Element | null);
  /** The `children` will be under the DOM hierarchy of the parent component. */
  disablePortal?: boolean;
  /** Always keep the children in the DOM. This prop can be useful in SEO situation or when you want to maximize the responsiv */
  keepMounted?: boolean;
  /** The components used for each slot inside. */
  components?: { Root?: React.ElementType; Backdrop?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { root?: SlotComponentProps<"div", ModalComponentsPropsOverrides, ModalOwnerState>; backdrop?: SlotComponentProps<OverridableComponent<BackdropTypeMap<{}, "div">>, ModalComponentsPropsOverrides, ModalOwnerState>; };
  /** A backdrop component. This prop enables custom backdrop rendering. */
  BackdropComponent?: React.ComponentClass<BackdropProps, any> | React.FunctionComponent<BackdropProps>;
  /** Props applied to the [`Backdrop`](https://mui.com/material-ui/api/backdrop/) element. */
  BackdropProps?: Partial<BackdropProps>;
  /** When set to true the Modal waits until a nested Transition is completed before closing. */
  closeAfterTransition?: boolean;
  /** If `true`, the modal will not automatically shift focus to itself when it opens, and replace it to the last focused elem */
  disableAutoFocus?: boolean;
  /** If `true`, the modal will not prevent focus from leaving the modal while open. Generally this should never be set to `tr */
  disableEnforceFocus?: boolean;
  /** If `true`, the modal will not restore focus to previously focused element once modal is hidden or unmounted. */
  disableRestoreFocus?: boolean;
  /** Disable the scroll lock behavior. */
  disableScrollLock?: boolean;
  /** If `true`, the backdrop is not rendered. */
  hideBackdrop?: boolean;
  /** The components used for each slot inside. */
  slots?: Partial<DialogSlots>;
  /** The props used for each slot inside. */
  slotProps?: unknown;
}
```

## Related

`DialogActions`, `DialogContent`, `DialogTitle`
