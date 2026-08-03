Chip from sberpcf-design-kit. Use via `window.SberDesignKit.Chip` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface ChipProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The Avatar element to display. */
  avatar?: React.ReactElement<unknown, string | React.JSXElementConstructor<any>>;
  /** This prop isn't supported. Use the `component` prop if you need to change the children structure. */
  children?: null;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ChipClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, the chip will appear clickable, and will raise when pressed, even if the onClick prop is not defined. If `fal */
  clickable?: boolean;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "default" | "primary" | "secondary";
  /** Override the default delete icon element. Shown only if `onDelete` is set. */
  deleteIcon?: React.ReactElement<unknown, string | React.JSXElementConstructor<any>>;
  /** If `true`, the component is disabled. */
  disabled?: boolean;
  /** Icon element. */
  icon?: React.ReactElement<unknown, string | React.JSXElementConstructor<any>>;
  /** The content of the component. */
  label?: React.ReactNode;
  /** The size of the component. */
  size?: "small" | "medium";
  /** If `true`, allows the disabled chip to escape focus. If `false`, allows the disabled chip to receive focus. */
  skipFocusWhenDisabled?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  tabIndex?: number;
  /** The variant to use. */
  variant?: "filled" | "outlined";
  className?: string;
  style?: React.CSSProperties;
}
```
