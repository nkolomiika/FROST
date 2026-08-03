ListItem from sberpcf-design-kit. Use via `window.SberDesignKit.ListItem` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface ListItemProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The components used for each slot inside. */
  components?: { Root?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { root?: React.HTMLAttributes<HTMLDivElement> & ListItemComponentsPropsOverrides; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  slotProps?: { root?: React.HTMLAttributes<HTMLDivElement> & ListItemComponentsPropsOverrides; };
  /** The components used for each slot inside. */
  slots?: { root?: React.ElementType; };
  /** Defines the `align-items` style property. */
  alignItems?: "center" | "flex-start";
  /** The content of the component if a `ListItemSecondaryAction` is used it must be the last child. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ListItemClasses> & Partial<ClassNameMap<never>>;
  /** The container component used when a `ListItemSecondaryAction` is the last child. */
  ContainerComponent?: "object" | "header" | "div" | "span" | "hr" | "table" | "tbody" | "thead" | "tr" | "abbr" | "address" | "article" | "aside" | "b" | "bdi" | "bdo" | (string & {}) /* +60 more */;
  /** Props applied to the container component if used. */
  ContainerProps?: React.HTMLAttributes<HTMLDivElement>;
  /** If `true`, compact vertical padding designed for keyboard and mouse input is used. The prop defaults to the value inheri */
  dense?: boolean;
  /** If `true`, the left and right padding is removed. */
  disableGutters?: boolean;
  /** If `true`, all padding is removed. */
  disablePadding?: boolean;
  /** If `true`, a 1px light border is added to the bottom of the list item. */
  divider?: boolean;
  /** The element to display at the end of ListItem. */
  secondaryAction?: React.ReactNode;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}
```

## Related

`ListItemButton`, `ListItemIcon`, `ListItemText`
