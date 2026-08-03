TableCell from sberpcf-design-kit. Use via `window.SberDesignKit.TableCell` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface TableCellProps {
  /** Set the text-align on the table cell content. Monetary or generally number fields **should be right aligned** as that al */
  align?: "center" | "left" | "right" | "inherit" | "justify";
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TableCellClasses>;
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component?: "header" | "div" | "span" | "abbr" | "address" | "article" | "aside" | "b" | "bdi" | "bdo" | "big" | "caption" | "center" | "cite" | "code" | "dd" | (string & {}) /* +46 more */;
  /** Sets the padding applied to the cell. The prop defaults to the value (`'default'`) inherited from the parent Table compo */
  padding?: "checkbox" | "none" | "normal";
  /** Set scope attribute. */
  scope?: string;
  /** Specify the size of the cell. The prop defaults to the value (`'medium'`) inherited from the parent Table component. */
  size?: "small" | "medium";
  /** Set aria-sort direction. */
  sortDirection?: false | "desc" | "asc";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** Specify the cell type. The prop defaults to the value inherited from the parent TableHead, TableBody, or TableFooter com */
  variant?: "body" | "footer" | "head";
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}
```
