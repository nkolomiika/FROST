CircularProgress from sberpcf-design-kit. Use via `window.SberDesignKit.CircularProgress` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface CircularProgressProps {
  /** Override or extend the styles applied to the component. */
  classes?: Partial<CircularProgressClasses>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "inherit" | "primary" | "secondary";
  /** If `true`, the shrink animation is disabled. This only works if variant is `indeterminate`. */
  disableShrink?: boolean;
  /** The size of the component. If using a number, the pixel unit is assumed. If using a string, you need to provide the CSS  */
  size?: string | number;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The thickness of the circle. */
  thickness?: number;
  /** The value of the progress indicator for the determinate variant. Value between 0 and 100. */
  value?: number;
  /** The variant to use. Use indeterminate when there is no progress value. */
  variant?: "indeterminate" | "determinate";
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}
```
