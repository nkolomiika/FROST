Table from sberpcf-design-kit. Use via `window.SberDesignKit.Table` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface TableProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the table, normally `TableHead` and `TableBody`. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TableClasses> & Partial<ClassNameMap<never>>;
  /** Allows TableCells to inherit padding of the Table. */
  padding?: "checkbox" | "none" | "normal";
  /** Allows TableCells to inherit size of the Table. */
  size?: "small" | "medium";
  /** Set the header sticky. */
  stickyHeader?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}
```

## Related

`TableBody`, `TableCell`, `TableContainer`, `TableHead`, `TableRow`
