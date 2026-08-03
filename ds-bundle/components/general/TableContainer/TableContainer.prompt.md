TableContainer from sberpcf-design-kit. Use via `window.SberDesignKit.TableContainer` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface TableContainerProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the component, normally `Table`. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TableContainerClasses> & Partial<ClassNameMap<never>>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
}
```
