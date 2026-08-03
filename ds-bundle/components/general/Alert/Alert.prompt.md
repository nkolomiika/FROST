Alert from sberpcf-design-kit. Use via `window.SberDesignKit.Alert` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface AlertProps {
  /** The action to display. It renders after the message, at the end of the alert. */
  action?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<AlertClasses>;
  /** Override the default label for the *close popup* icon button. For localization purposes, you can use the provided [trans */
  closeText?: string;
  /** The color of the component. Unless provided, the value is taken from the `severity` prop. It supports both default and c */
  color?: "success" | "info" | "warning" | "error";
  /** The components used for each slot inside. */
  components?: { CloseButton?: React.ElementType; CloseIcon?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { closeButton?: IconButtonProps; closeIcon?: SvgIconProps; };
  /** The severity of the alert. This defines the color and icon used. */
  severity?: "success" | "info" | "warning" | "error";
  /** Override the icon displayed before the children. Unless provided, the icon is mapped to the value of the `severity` prop */
  icon?: React.ReactNode;
  /** The ARIA role attribute of the element. */
  role?: string;
  /** The component maps the `severity` prop to a range of different icons, for instance success to `<SuccessOutlined>`. If yo */
  iconMapping?: Partial<Record<OverridableStringUnion<AlertColor, AlertPropsColorOverrides>, React.ReactNode>>;
  /** The variant to use. */
  variant?: "filled" | "outlined" | "standard";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Shadow depth, corresponds to `dp` in the spec. It accepts values between 0 and 24 inclusive. */
  elevation?: number;
  /** If `true`, rounded corners are disabled. */
  square?: boolean;
  ref?: React.Ref;
  id?: string;
  component?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** The components used for each slot inside. */
  slots?: Partial<AlertSlots>;
  /** The props used for each slot inside. */
  slotProps?: unknown;
}
```
