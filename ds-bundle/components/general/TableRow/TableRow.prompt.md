TableRow from sberpcf-design-kit. Use via `window.SberDesignKit.TableRow` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface TableRowProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Should be valid `<tr>` children such as `TableCell`. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TableRowClasses> & Partial<ClassNameMap<never>>;
  /** If `true`, the table row will shade on hover. */
  hover?: boolean;
  /** If `true`, the table row will have the selected shading. */
  selected?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}
```
