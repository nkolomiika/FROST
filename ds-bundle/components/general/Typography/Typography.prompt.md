Typography from sberpcf-design-kit. Use via `window.SberDesignKit.Typography` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface TypographyProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Set the text-align on the component. */
  align?: "center" | "left" | "right" | "inherit" | "justify";
  /** The content of the component. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TypographyClasses> & Partial<ClassNameMap<never>>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | string & {} | "primary" | "secondary" | "textPrimary" | "textSecondary" | "textDisabled";
  /** If `true`, the text will have a bottom margin. */
  gutterBottom?: boolean;
  /** If `true`, the text will not wrap, but instead will truncate with a text overflow ellipsis. Note that text overflow can  */
  noWrap?: boolean;
  /** If `true`, the element will be a paragraph element. */
  paragraph?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** Applies the theme typography styles. */
  variant?: "button" | "caption" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "inherit" | "subtitle1" | "subtitle2" | "body1" | "body2" | "overline";
  /** The component maps the variant prop to a range of different HTML element types. For instance, subtitle1 to `<h6>`. If yo */
  variantMapping?: Partial<Record<OverridableStringUnion<"inherit" | Variant, TypographyPropsVariantOverrides>, string>>;
  p?: unknown;
  border?: number | "hidden" | string & {} | "inset" | "none" | "inherit" | "medium" | "initial" | "transparent" | "-moz-initial" | "revert" | "revert-layer" | "unset" | "aliceblue" | "antiquewhite" | "aqua" | (string & {}) /* +198 more */;
  boxShadow?: unknown;
  fontWeight?: string | string & {} | number & {} | readonly (string | (string & {}) | (number & {}))[] | { [key: string]: string | (string & {}) | (number & {}); } | ((theme: Theme) => ResponsiveStyleValue<string | (string & {}) | (number & {})>);
  zIndex?: string | string & {} | number & {} | readonly (string | (string & {}) | (number & {}))[] | { [key: string]: string | (string & {}) | (number & {}); } | ((theme: Theme) => ResponsiveStyleValue<string | (string & {}) | (number & {})>);
  alignContent?: unknown;
  alignItems?: unknown;
  alignSelf?: unknown;
  bottom?: unknown;
  boxSizing?: unknown;
  columnGap?: unknown;
  display?: "table" | "ruby" | string & {} | "flex" | "grid" | "none" | "inline" | readonly string[] | "inherit" | "initial" | "-moz-initial" | "revert" | "revert-layer" | "unset" | "block" | "run-in" | (string & {}) /* +30 more */;
  flexBasis?: unknown;
  flexDirection?: unknown;
  flexGrow?: unknown;
  flexShrink?: unknown;
  flexWrap?: unknown;
  fontFamily?: unknown;
  fontSize?: unknown;
  fontStyle?: unknown;
  gridAutoColumns?: unknown;
  gridAutoFlow?: unknown;
  gridAutoRows?: unknown;
  gridTemplateAreas?: unknown;
  gridTemplateColumns?: unknown;
  gridTemplateRows?: unknown;
  height?: unknown;
  justifyContent?: unknown;
  justifyItems?: "center" | string & {} | "left" | "right" | "end" | readonly string[] | "inherit" | "baseline" | "initial" | "start" | "-moz-initial" | "revert" | "revert-layer" | "unset" | "normal" | "stretch" | (string & {}) /* +9 more */;
  justifySelf?: "center" | string & {} | "left" | "right" | "end" | readonly string[] | "inherit" | "auto" | "baseline" | "initial" | "start" | "-moz-initial" | "revert" | "revert-layer" | "unset" | "normal" | (string & {}) /* +9 more */;
  left?: unknown;
  letterSpacing?: unknown;
  lineHeight?: unknown;
  marginBlockEnd?: unknown;
  marginBlockStart?: unknown;
  marginBottom?: unknown;
  marginInlineEnd?: unknown;
  marginInlineStart?: unknown;
  marginLeft?: unknown;
  marginRight?: unknown;
  marginTop?: unknown;
  maxHeight?: unknown;
  maxWidth?: unknown;
  minHeight?: unknown;
  minWidth?: unknown;
  order?: unknown;
  paddingBlockEnd?: unknown;
  paddingBlockStart?: unknown;
  paddingBottom?: unknown;
  paddingInlineEnd?: unknown;
  paddingInlineStart?: unknown;
  paddingLeft?: unknown;
  paddingRight?: unknown;
  paddingTop?: unknown;
  position?: unknown;
  right?: unknown;
  rowGap?: unknown;
  textAlign?: "center" | "left" | "right" | "end" | "inherit" | "initial" | "start" | "-moz-initial" | "revert" | "revert-layer" | "unset" | "-khtml-center" | "-khtml-left" | "-khtml-right" | "-moz-center" | "-moz-left" | (string & {}) /* +11 more */;
  textOverflow?: unknown;
  textTransform?: unknown;
  top?: unknown;
  visibility?: unknown;
  whiteSpace?: unknown;
  width?: unknown;
  borderBottom?: unknown;
  borderColor?: unknown;
  borderLeft?: unknown;
  borderRadius?: unknown;
  borderRight?: unknown;
  borderTop?: unknown;
  flex?: unknown;
  gap?: unknown;
  gridArea?: unknown;
  gridColumn?: unknown;
  gridRow?: unknown;
  margin?: unknown;
  marginBlock?: unknown;
  marginInline?: unknown;
  overflow?: unknown;
  padding?: unknown;
  paddingBlock?: unknown;
  paddingInline?: unknown;
  bgcolor?: unknown;
  m?: unknown;
  mt?: unknown;
  mr?: unknown;
  mb?: unknown;
  ml?: unknown;
  mx?: unknown;
  marginX?: unknown;
  my?: unknown;
  marginY?: unknown;
  pt?: unknown;
  pr?: unknown;
  pb?: unknown;
  pl?: unknown;
  px?: unknown;
  paddingX?: unknown;
  py?: unknown;
  paddingY?: unknown;
  typography?: string | readonly string[] | { [key: string]: string; } | ((theme: Theme) => ResponsiveStyleValue<string>);
  displayPrint?: "table" | "ruby" | string & {} | "flex" | "grid" | "none" | "inline" | readonly string[] | "inherit" | "initial" | "-moz-initial" | "revert" | "revert-layer" | "unset" | "block" | "run-in" | (string & {}) /* +30 more */;
  className?: string;
  style?: React.CSSProperties;
}
```
