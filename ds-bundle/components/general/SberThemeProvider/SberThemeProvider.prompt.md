SberThemeProvider from sberpcf-design-kit. Use via `window.SberDesignKit.SberThemeProvider` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface SberThemeProviderProps {
  /** The application tree to render inside the themed context. */
  children?: React.ReactNode;
}
```
