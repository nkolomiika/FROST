DialogContent from sberpcf-design-kit. Use via `window.SberDesignKit.DialogContent` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface DialogContentProps {
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<DialogContentClasses>;
  /** Display the top and bottom dividers. */
  dividers?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}
```
