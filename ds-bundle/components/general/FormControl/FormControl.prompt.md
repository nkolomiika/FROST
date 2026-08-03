FormControl from sberpcf-design-kit. Use via `window.SberDesignKit.FormControl` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface FormControlProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<FormControlClasses> & Partial<ClassNameMap<never>>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "primary" | "secondary";
  /** If `true`, the label, input and helper text should be displayed in a disabled state. */
  disabled?: boolean;
  /** If `true`, the label is displayed in an error state. */
  error?: boolean;
  /** If `true`, the component will take up the full width of its container. */
  fullWidth?: boolean;
  /** If `true`, the component is displayed in focused state. */
  focused?: boolean;
  /** If `true`, the label is hidden. This is used to increase density for a `FilledInput`. Be sure to add `aria-label` to the */
  hiddenLabel?: boolean;
  /** If `dense` or `normal`, will adjust vertical spacing of this and contained components. */
  margin?: "none" | "normal" | "dense";
  /** If `true`, the label will indicate that the `input` is required. */
  required?: boolean;
  /** The size of the component. */
  size?: "small" | "medium";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The variant to use. */
  variant?: "filled" | "outlined" | "standard";
  className?: string;
  style?: React.CSSProperties;
}
```

## Related

`FormControlLabel`
