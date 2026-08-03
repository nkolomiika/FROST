# SberDesignKit (sberpcf-design-kit@1.0.0)

This design system is the published sberpcf-design-kit React library, bundled as a single
browser global. All 51 components are the real upstream code.

## Where things are

- `_ds_bundle.js` — the whole-DS bundle at the project root; loads every component to `window.SberDesignKit`. First line is a `/* @ds-bundle: … */` metadata header.
- `styles.css` — the single stylesheet entry (tokens and fonts; this DS injects component styles at runtime). Link this one file.
- `components/<group>/<Name>/<Name>.prompt.md` (example JSX + variants), `<Name>.d.ts` (types), `<Name>.html` (variant grid).
- `tokens/*.css` — CSS custom properties, names verbatim from upstream.
- `fonts/` — `@font-face` files + `fonts.css` (when the package ships fonts).

For a specific component, `read_file("components/<group>/<Name>/<Name>.prompt.md")`.

## Loading

Add these two lines to your page once (React must be on the page first):

```html
<link rel="stylesheet" href="styles.css">
<script src="_ds_bundle.js"></script>
```

Components are then available at `window.SberDesignKit.*`. Mount into a dedicated child node (e.g. `<div id="ds-root">`), not the host page's own React root, so the two trees don't collide:

```jsx
const { Alert } = window.SberDesignKit;
ReactDOM.createRoot(document.getElementById('ds-root')).render(<Alert />);
```

Wrap the tree in the provider — most components read theme/i18n from context:

```jsx
<SberThemeProvider>{children}</SberThemeProvider>
```

## Tokens

0 CSS custom properties from sberpcf-design-kit. Names are
preserved verbatim from upstream. None detected — this DS may compute styles at runtime (CSS-in-JS).



## Components

### general
- `Alert` — Demos:
- `AppBar` — Demos:
- `Autocomplete` — Demos:
- `Avatar` — Demos:
- `Badge` — Demos:
- `Box` — Demos:
- `Button` — Demos:
- `Card` — Demos:
- `CardContent` — Demos:
- `Checkbox` — Demos:
- `Chip` — Chips represent complex entities in small blocks, such as a contact.
- `CircularProgress` —  ARIA
- `Container` — Demos:
- `Dialog` — Dialogs are overlaid modal paper based components with a backdrop.
- `DialogActions` — Demos:
- `DialogContent` — Demos:
- `DialogTitle` — Demos:
- `Divider` — Demos:
- `FormControl` — Provides context such as filled/focused/error/required for form inputs.
- `FormControlLabel` — Drop-in replacement of the Radio, Switch and Checkbox component.
- `FormGroup` — FormGroup wraps controls such as Checkbox and Switch.
- `Grid` — Demos:
- `IconButton` — Refer to the Icons(https://v6.mui.com/material-ui/icons/) section of the documentation
- `InputAdornment` — Demos:
- `InputLabel` — Demos:
- `LinearProgress` —  ARIA
- `List` — Demos:
- `ListItem` — Uses an additional container component if ListItemSecondaryAction is the last child.
- `ListItemButton` — Demos:
- `ListItemIcon` — A simple wrapper to apply List styles to an Icon or SvgIcon.
- `ListItemText` — Demos:
- `Menu` — Demos:
- `MenuItem` — Demos:
- `OutlinedInput` — Demos:
- `Pagination` — Demos:
- `Paper` — Demos:
- `Popover` — Demos:
- `SberThemeProvider` — Root provider for the SberPCF design system.
- `Select` — Demos:
- `Stack` — Demos:
- `Switch` — Demos:
- `Table` — Demos:
- `TableBody` — Demos:
- `TableCell` — The component renders a th element when the parent context is a header
- `TableContainer` — Demos:
- `TableHead` — Demos:
- `TableRow` — Will automatically set dynamic row height
- `TextField` — The TextField is a convenience wrapper for the most common cases (80).
- `Toolbar` — Demos:
- `Tooltip` — Demos:
- `Typography` — Demos:
