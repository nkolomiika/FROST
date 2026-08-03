ListItemIcon from sberpcf-design-kit. Use via `window.SberDesignKit.ListItemIcon` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface ListItemIconProps {
  /** The content of the component, normally `Icon`, `SvgIcon`, or a `@mui/icons-material` SVG icon element. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ListItemIconClasses>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}
```
