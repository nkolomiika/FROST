LinearProgress from sberpcf-design-kit. Use via `window.SberDesignKit.LinearProgress` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface LinearProgressProps {
  /** Override or extend the styles applied to the component. */
  classes?: Partial<LinearProgressClasses>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "inherit" | "primary" | "secondary";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The value of the progress indicator for the determinate and buffer variants. Value between 0 and 100. */
  value?: number;
  /** The value for the buffer variant. Value between 0 and 100. */
  valueBuffer?: number;
  /** The variant to use. Use indeterminate or query when there is no progress value. */
  variant?: "indeterminate" | "determinate" | "buffer" | "query";
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}
```
