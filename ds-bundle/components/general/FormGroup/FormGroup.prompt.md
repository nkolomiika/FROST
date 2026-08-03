FormGroup from sberpcf-design-kit. Use via `window.SberDesignKit.FormGroup` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface FormGroupProps {
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<FormGroupClasses>;
  /** Display group of elements in a compact row. */
  row?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}
```
