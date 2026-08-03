Select from sberpcf-design-kit. Use via `window.SberDesignKit.Select` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface SelectProps {
  /** The variant to use. */
  variant?: "filled" | "outlined" | "standard";
  className?: string;
  style?: React.CSSProperties;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  ref?: React.Ref;
  /** The default value. Use when the component is not controlled. */
  defaultValue?: Value;
  /** If `true`, the `input` element is focused during the first mount. */
  autoFocus?: boolean;
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
  /** This prop helps users to fill forms faster, especially on mobile devices. The name can be confusing, as it's more like a */
  autoComplete?: string;
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
  /** The extra props for the slot components. You can override the existing props or add new ones. This prop is an alias for  */
  slotProps?: { root?: React.HTMLAttributes<HTMLDivElement> & InputBaseComponentsPropsOverrides & { sx?: SxProps<Theme>; }; input?: React.InputHTMLAttributes<HTMLInputElement> & InputBaseComponentsPropsOverrides & { sx?: SxProps<Theme>; }; } | unknown;
  /** The components used for each slot inside. This prop is an alias for the `components` prop, which will be deprecated in t */
  slots?: { root?: React.ElementType; input?: React.ElementType; } | Partial<OutlinedInputSlots> & { root?: React.ElementType; input?: React.ElementType; };
  /** The components used for each slot inside. */
  components?: { Root?: React.ElementType; Input?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: { root?: React.HTMLAttributes<HTMLDivElement> & InputBaseComponentsPropsOverrides; input?: React.InputHTMLAttributes<HTMLInputElement> & InputBaseComponentsPropsOverrides; };
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
  /** If `true`, the input will not have an underline. */
  disableUnderline?: boolean;
  /** If `true`, the width of the popover will automatically be set according to the items inside the menu, otherwise it will  */
  autoWidth?: boolean;
  /** The option elements to populate the select with. Can be some `MenuItem` when `native` is false and `option` when `native */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<SelectClasses>;
  /** If `true`, the component is initially open. Use when the component open state is not controlled (i.e. the `open` prop is */
  defaultOpen?: boolean;
  /** If `true`, a value is displayed even if no items are selected. In order to display a meaningful value, a function can be */
  displayEmpty?: boolean;
  /** The icon that displays the arrow. */
  IconComponent?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** The `id` of the wrapper element or the `select` element when `native`. */
  id?: string;
  /** An `Input` element; does not have to be a material-ui specific `Input`. */
  input?: React.ReactElement<unknown, any>;
  /** [Attributes](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input#Attributes) applied to the `input` element. */
  inputProps?: InputBaseComponentProps;
  /** See [OutlinedInput#label](https://mui.com/material-ui/api/outlined-input/#props) */
  label?: React.ReactNode;
  /** The ID of an element that acts as an additional label. The Select will be labelled by the additional label and the selec */
  labelId?: string;
  /** Props applied to the [`Menu`](https://mui.com/material-ui/api/menu/) element. */
  MenuProps?: Partial<MenuProps>;
  /** If `true`, `value` must be an array and the menu will support multiple selections. */
  multiple?: boolean;
  /** If `true`, the component uses a native `select` element. */
  native?: boolean;
  /** If `true`, the component is shown. You can only use it when the `native` prop is `false` (default). */
  open?: boolean;
  /** Render the selected value. You can only use it when the `native` prop is `false` (default). */
  renderValue?: (value: Value) => React.ReactNode;
  /** Props applied to the clickable div element. */
  SelectDisplayProps?: React.HTMLAttributes<HTMLDivElement>;
  /** The `input` value. Providing an empty string will select no options. Set to an empty string `''` if you don't want any o */
  value?: "" | Value;
}
```
