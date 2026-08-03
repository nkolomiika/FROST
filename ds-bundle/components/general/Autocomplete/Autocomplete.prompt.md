Autocomplete from sberpcf-design-kit. Use via `window.SberDesignKit.Autocomplete` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface AutocompleteProps {
  /** Props applied to the [`Chip`](https://mui.com/material-ui/api/chip/) element. */
  ChipProps?: ChipProps<ChipComponent>;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<AutocompleteClasses>;
  /** The icon to display in place of the default clear icon. */
  clearIcon?: React.ReactNode;
  /** Override the default text for the *clear* icon button. For localization purposes, you can use the provided [translations */
  clearText?: string;
  /** Override the default text for the *close popup* icon button. For localization purposes, you can use the provided [transl */
  closeText?: string;
  /** The props used for each slot inside. */
  componentsProps?: { clearIndicator?: Partial<IconButtonProps>; paper?: PaperProps; popper?: Partial<PopperProps>; popupIndicator?: Partial<IconButtonProps>; };
  /** If `true`, the component is disabled. */
  disabled?: boolean;
  /** If `true`, the `Popper` content will be under the DOM hierarchy of the parent component. */
  disablePortal?: boolean;
  /** Force the visibility display of the popup icon. */
  forcePopupIcon?: boolean | "auto";
  /** If `true`, the input will take up the full width of its container. */
  fullWidth?: boolean;
  /** The label to display when the tags are truncated (`limitTags`). */
  getLimitTagsText?: (more: number) => React.ReactNode;
  /** The component used to render the listbox. */
  ListboxComponent?: ((props: React.HTMLAttributes<HTMLElement>, deprecatedLegacyContext?: any) => React.ReactNode) | (new (props: React.HTMLAttributes<HTMLElement>, deprecatedLegacyContext?: any) => React.Component<any, any>);
  /** Props applied to the Listbox element. */
  ListboxProps?: React.HTMLAttributes<HTMLUListElement> & { sx?: SxProps<Theme>; ref?: React.Ref<Element>; };
  /** If `true`, the component is in a loading state. This shows the `loadingText` in place of suggestions (only if there are  */
  loading?: boolean;
  /** Text to display when in a loading state. For localization purposes, you can use the provided [translations](https://mui. */
  loadingText?: React.ReactNode;
  /** The maximum number of tags that will be visible when not focused. Set `-1` to disable the limit. */
  limitTags?: number;
  /** Text to display when there are no options. For localization purposes, you can use the provided [translations](https://mu */
  noOptionsText?: React.ReactNode;
  /** Override the default text for the *open popup* icon button. For localization purposes, you can use the provided [transla */
  openText?: string;
  /** The component used to render the body of the popup. */
  PaperComponent?: ((props: React.HTMLAttributes<HTMLElement>, deprecatedLegacyContext?: any) => React.ReactNode) | (new (props: React.HTMLAttributes<HTMLElement>, deprecatedLegacyContext?: any) => React.Component<any, any>);
  /** The component used to position the popup. */
  PopperComponent?: ((props: PopperProps, deprecatedLegacyContext?: any) => React.ReactNode) | (new (props: PopperProps, deprecatedLegacyContext?: any) => React.Component<any, any>);
  /** The icon to display in place of the default popup icon. */
  popupIcon?: React.ReactNode;
  /** If `true`, the component becomes readonly. It is also supported for multiple tags where the tag cannot be deleted. */
  readOnly?: boolean;
  /** Render the group. */
  renderGroup?: (params: AutocompleteRenderGroupParams) => React.ReactNode;
  /** Render the input. */
  renderInput: (params: AutocompleteRenderInputParams) => React.ReactNode;
  /** Render the option, use `getOptionLabel` by default. */
  renderOption?: (props: React.HTMLAttributes<HTMLLIElement> & { key: any; }, option: Value, state: AutocompleteRenderOptionState, ownerState: AutocompleteOwnerState<Value, Multiple, DisableClearable, FreeSolo, ChipComponent>) => React.ReactNode;
  /** Render the selected value. */
  renderTags?: (value: Value[], getTagProps: AutocompleteRenderGetTagProps, ownerState: AutocompleteOwnerState<Value, Multiple, DisableClearable, FreeSolo, ChipComponent>) => React.ReactNode;
  /** The size of the component. */
  size?: "small" | "medium";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  unstable_classNamePrefix?: string;
  unstable_isActiveElementInListbox?: (listbox: React.RefObject<HTMLElement | null>) => boolean;
  /** If `true`, the portion of the selected suggestion that the user hasn't typed, known as the completion string, appears in */
  autoComplete?: boolean;
  /** If `true`, the first option is automatically highlighted. */
  autoHighlight?: boolean;
  /** If `true`, the selected option becomes the value of the input when the Autocomplete loses focus unless the user chooses  */
  autoSelect?: boolean;
  /** Control if the input should be blurred when an option is selected: - `false` the input is not blurred. - `true` the inpu */
  blurOnSelect?: boolean | "mouse" | "touch";
  /** If `true`, the input's text is cleared on blur if no value is selected. Set it to `true` if you want to help the user en */
  clearOnBlur?: boolean;
  /** If `true`, clear all values when the user presses escape and the popup is closed. */
  clearOnEscape?: boolean;
  /** The component name that is using this hook. Used for warnings. */
  componentName?: string;
  /** The default value. Use when the component is not controlled. */
  defaultValue?: AutocompleteValue<Value, Multiple, DisableClearable, FreeSolo>;
  /** If `true`, the input can't be cleared. */
  disableClearable?: DisableClearable;
  /** If `true`, the popup won't close when a value is selected. */
  disableCloseOnSelect?: boolean;
  /** If `true`, will allow focus on disabled items. */
  disabledItemsFocusable?: boolean;
  /** If `true`, the list box in the popup will not wrap focus. */
  disableListWrap?: boolean;
  /** A function that determines the filtered options to be rendered on search. */
  filterOptions?: (options: Value[], state: FilterOptionsState<Value>) => Value[];
  /** If `true`, hide the selected options from the list box. */
  filterSelectedOptions?: boolean;
  /** If `true`, the Autocomplete is free solo, meaning that the user input is not bound to provided options. */
  freeSolo?: FreeSolo;
  /** Used to determine the disabled state for a given option. */
  getOptionDisabled?: (option: Value) => boolean;
  /** Used to determine the key for a given option. This can be useful when the labels of options are not unique (since labels */
  getOptionKey?: (option: Value | AutocompleteFreeSoloValueMapping<FreeSolo>) => string | number;
  /** Used to determine the string value for a given option. It's used to fill the input (and the list box options if `renderO */
  getOptionLabel?: (option: Value | AutocompleteFreeSoloValueMapping<FreeSolo>) => string;
  /** If provided, the options will be grouped under the returned string. The groupBy value is also used as the text for group */
  groupBy?: (option: Value) => string;
  /** If `true`, the component handles the "Home" and "End" keys when the popup is open. It should move focus to the first opt */
  handleHomeEndKeys?: boolean;
  /** This prop is used to help implement the accessibility logic. If you don't provide an id it will fall back to a randomly  */
  id?: string;
  /** If `true`, the highlight can move to the input. */
  includeInputInList?: boolean;
  /** The input value. */
  inputValue?: string;
  /** Used to determine if the option represents the given value. Uses strict equality by default. ⚠️ Both arguments need to b */
  isOptionEqualToValue?: (option: Value, value: Value) => boolean;
  /** If `true`, `value` must be an array and the menu will support multiple selections. */
  multiple?: Multiple;
  /** If `true`, the component is shown. */
  open?: boolean;
  /** If `true`, the popup will open on input focus. */
  openOnFocus?: boolean;
  /** A list of options that will be shown in the Autocomplete. */
  options: readonly Value[];
  /** If `true`, the input's text is selected on focus. It helps the user clear the selected value. */
  selectOnFocus?: boolean;
  /** The value of the autocomplete. The value must have reference equality with the option in order to be selected. You can c */
  value?: AutocompleteValue<Value, Multiple, DisableClearable, FreeSolo>;
  className?: string;
  style?: React.CSSProperties;
  ref?: React.Ref;
  /** The components used for each slot inside. */
  slots?: Partial<AutocompleteSlots>;
  /** The props used for each slot inside. */
  slotProps?: unknown;
}
```
