IconButton from sberpcf-design-kit. Use via `window.SberDesignKit.IconButton` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface IconButtonProps {
  href: string;
  /** The icon to display. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<IconButtonClasses> & Partial<ClassNameMap<never>>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "inherit" | "default" | "primary" | "secondary";
  /** If `true`, the component is disabled. */
  disabled?: boolean;
  /** If `true`, the keyboard focus ripple is disabled. */
  disableFocusRipple?: boolean;
  /** If given, uses a negative margin to counteract the padding on one side (this is often helpful for aligning the left or r */
  edge?: false | "end" | "start";
  /** If `true`, the loading indicator is visible and the button is disabled. If `true | false`, the loading wrapper is always */
  loading?: boolean;
  /** Element placed before the children if the button is in loading state. The node should contain an element with `role="pro */
  loadingIndicator?: React.ReactNode;
  /** The size of the component. `small` is equivalent to the dense button styling. */
  size?: "small" | "large" | "medium";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  tabIndex?: number;
  /** A ref for imperative actions. It currently only supports `focusVisible()` action. */
  action?: React.Ref;
  /** If `true`, the ripples are centered. They won't start at the cursor interaction position. */
  centerRipple?: boolean;
  /** If `true`, the ripple effect is disabled. ⚠️ Without a ripple there is no styling for :focus-visible by default. Be sure */
  disableRipple?: boolean;
  /** If `true`, the touch ripple effect is disabled. */
  disableTouchRipple?: boolean;
  /** If `true`, the base button will have a keyboard focus ripple. */
  focusRipple?: boolean;
  /** This prop can help identify which element has keyboard focus. The class name will be applied when the element gains the  */
  focusVisibleClassName?: string;
  /** The component used to render a link when the `href` prop is provided. */
  LinkComponent?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** Props applied to the `TouchRipple` element. */
  TouchRippleProps?: Partial<TouchRippleProps>;
  /** A ref that points to the `TouchRipple` element. */
  touchRippleRef?: React.Ref;
  className?: string;
  style?: React.CSSProperties;
  ref?: React.Ref;
  id?: string;
}
```
