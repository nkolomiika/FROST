Pagination from sberpcf-design-kit. Use via `window.SberDesignKit.Pagination` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface PaginationProps {
  /** Override or extend the styles applied to the component. */
  classes?: Partial<PaginationClasses>;
  /** The active color. It supports both default and custom theme colors, which can be added as shown in the [palette customiz */
  color?: "standard" | "primary" | "secondary";
  /** Accepts a function which returns a string value that provides a user-friendly name for the current page. This is importa */
  getItemAriaLabel?: (type: UsePaginationItem["type"], page: UsePaginationItem["page"], selected: UsePaginationItem["selected"]) => string;
  /** Render the item. */
  renderItem?: (params: PaginationRenderItemParams) => React.ReactNode;
  /** The shape of the pagination items. */
  shape?: "circular" | "rounded";
  /** The size of the component. */
  size?: "small" | "large" | "medium";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The variant to use. */
  variant?: "text" | "outlined";
  /** Number of always visible pages at the beginning and end. */
  boundaryCount?: number;
  /** The name of the component where this hook is used. */
  componentName?: string;
  /** The total number of pages. */
  count?: number;
  /** The page selected by default when the component is uncontrolled. */
  defaultPage?: number;
  /** If `true`, the component is disabled. */
  disabled?: boolean;
  /** If `true`, hide the next-page button. */
  hideNextButton?: boolean;
  /** If `true`, hide the previous-page button. */
  hidePrevButton?: boolean;
  /** The current page. Unlike `TablePagination`, which starts numbering from `0`, this pagination starts from `1`. */
  page?: number;
  /** If `true`, show the first-page button. */
  showFirstButton?: boolean;
  /** If `true`, show the last-page button. */
  showLastButton?: boolean;
  /** Number of always visible pages before and after the current page. */
  siblingCount?: number;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
}
```
