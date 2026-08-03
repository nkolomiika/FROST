MenuItem from sberpcf-design-kit. Use via `window.SberDesignKit.MenuItem` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface MenuItemProps {
  href: string;
  /** If `true`, the list item is focused during the first mount. Focus will also be triggered if the value changes from false */
  autoFocus?: boolean;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<MenuItemClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, compact vertical padding designed for keyboard and mouse input is used. The prop defaults to the value inheri */
  dense?: boolean;
  /** If `true`, the component is disabled. */
  disabled?: boolean;
  /** If `true`, the left and right padding is removed. */
  disableGutters?: boolean;
  /** If `true`, a 1px light border is added to the bottom of the menu item. */
  divider?: boolean;
  /** If `true`, the component is selected. */
  selected?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The content of the component. */
  children?: React.ReactNode;
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
