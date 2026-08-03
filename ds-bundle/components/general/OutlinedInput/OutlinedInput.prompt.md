OutlinedInput from sberpcf-design-kit. Use via `window.SberDesignKit.OutlinedInput` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface OutlinedInputProps {
  /** Override or extend the styles applied to the component. */
  classes?: Partial<OutlinedInputClasses>;
  /** The label of the `input`. It is only used for layout. The actual labelling is handled by `InputLabel`. */
  label?: React.ReactNode;
  /** If `true`, the outline is notched to accommodate the label. */
  notched?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  className?: string;
  style?: React.CSSProperties;
  ref?: React.Ref;
  /** The default value. Use when the component is not controlled. */
  defaultValue?: unknown;
  /** If `true`, the `input` element is focused during the first mount. */
  autoFocus?: boolean;
  /** The id of the `input` element. */
  id?: string;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "primary" | "secondary";
  /** If `true`, the `input` will indicate an error. The prop defaults to the value (`false`) inherited from the parent FormCo */
  error?: boolean;
  /** If `true`, the component is disabled. The prop defaults to the value (`false`) inherited from the parent FormControl com */
  disabled?: boolean;
  /** If `dense`, will adjust vertical spacing. This is normally obtained via context from FormControl. The prop defaults to t */
  margin?: "none" | "dense";
  /** The size of the component. */
  size?: "small" | "medium";
  /** Name attribute of the `input` element. */
  name?: string;
  /** Type of the `input` element. It should be [a valid HTML5 input type](https://developer.mozilla.org/en-US/docs/Web/HTML/E */
  type?: string;
  /** The value of the `input` element, required for a controlled component. */
  value?: unknown;
  /** This prop helps users to fill forms faster, especially on mobile devices. The name can be confusing, as it's more like a */
  autoComplete?: string;
  /** The short hint displayed in the `input` before the user enters a value. */
  placeholder?: string;
  /** It prevents the user from changing the value of the field (not from interacting with the field). */
  readOnly?: boolean;
  /** If `true`, the `input` element is required. The prop defaults to the value (`false`) inherited from the parent FormContr */
  required?: boolean;
  /** Number of rows to display when multiline option is set to true. */
  rows?: string | number;
  /** If `true`, the `input` will take up the full width of its container. */
  fullWidth?: boolean;
  /** End `InputAdornment` for this component. */
  endAdornment?: React.ReactNode;
  /** The components used for each slot inside. */
  components?: { Root?: React.ElementType; Input?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { root?: React.HTMLAttributes<HTMLDivElement> & InputBaseComponentsPropsOverrides; input?: React.InputHTMLAttributes<HTMLInputElement> & InputBaseComponentsPropsOverrides; };
  /** [Attributes](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input#Attributes) applied to the `input` element. */
  inputProps?: InputBaseComponentProps;
  /** Pass a ref to the `input` element. */
  inputRef?: React.Ref;
  /** If `true`, a [TextareaAutosize](https://mui.com/material-ui/react-textarea-autosize/) element is rendered. */
  multiline?: boolean;
  /** If `true`, GlobalStyles for the auto-fill keyframes will not be injected/removed on mount/unmount. Make sure to inject t */
  disableInjectingGlobalStyles?: boolean;
  /** The component used for the `input` element. Either a string to use a HTML element or a component. */
  inputComponent?: "header" | "span" | "abbr" | "address" | "article" | "aside" | "b" | "bdi" | "bdo" | "big" | "caption" | "center" | "cite" | "code" | "data" | "dd" | (string & {}) /* +39 more */;
  renderSuffix?: (state: { disabled?: boolean; error?: boolean; filled?: boolean; focused?: boolean; margin?: "dense" | "none" | "normal"; required?: boolean; startAdornment?: React.ReactNode; }) => React.ReactNode;
  /** Maximum number of rows to display when multiline option is set to true. */
  maxRows?: string | number;
  /** Minimum number of rows to display when multiline option is set to true. */
  minRows?: string | number;
  /** Start `InputAdornment` for this component. */
  startAdornment?: React.ReactNode;
  /** The components used for each slot inside. */
  slots?: Partial<OutlinedInputSlots> & { root?: React.ElementType; input?: React.ElementType; };
  /** The props used for each slot inside. */
  slotProps?: unknown;
}
```
