Grid from sberpcf-design-kit. Use via `window.SberDesignKit.Grid` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface GridProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: C;
  /** The content of the component. */
  children?: React.ReactNode;
  /** The number of columns. */
  columns?: number | number[] | { xs?: number; sm?: number; md?: number; lg?: number; xl?: number; };
  /** Defines the horizontal space between the type `item` components. It overrides the value of the `spacing` prop. */
  columnSpacing?: string | number | GridSpacing[] | { xs?: GridSpacing; sm?: GridSpacing; md?: GridSpacing; lg?: GridSpacing; xl?: GridSpacing; };
  /** If `true`, the component will have the flex *container* behavior. You should be wrapping *items* with a *container*. */
  container?: boolean;
  /** Defines the `flex-direction` style property. It is applied for all screen sizes. */
  direction?: "row" | "column" | "column-reverse" | "row-reverse" | GridDirection[] | { xs?: GridDirection; sm?: GridDirection; md?: GridDirection; lg?: GridDirection; xl?: GridDirection; };
  /** Defines the offset value for the type `item` components. */
  offset?: number | "auto" | GridOffset[] | { xs?: GridOffset; sm?: GridOffset; md?: GridOffset; lg?: GridOffset; xl?: GridOffset; };
  unstable_level?: number;
  /** Defines the vertical space between the type `item` components. It overrides the value of the `spacing` prop. */
  rowSpacing?: string | number | GridSpacing[] | { xs?: GridSpacing; sm?: GridSpacing; md?: GridSpacing; lg?: GridSpacing; xl?: GridSpacing; };
  /** Defines the size of the the type `item` components. */
  size?: number | false | "auto" | "grow" | GridSize[] | { xs?: GridSize; sm?: GridSize; md?: GridSize; lg?: GridSize; xl?: GridSize; };
  /** Defines the space between the type `item` components. It can only be used on a type `container` component. */
  spacing?: string | number | GridSpacing[] | { xs?: GridSpacing; sm?: GridSpacing; md?: GridSpacing; lg?: GridSpacing; xl?: GridSpacing; };
  /** Defines the `flex-wrap` style property. It's applied for all screen sizes. */
  wrap?: "wrap" | "nowrap" | "wrap-reverse";
  sx?: unknown;
  p?: unknown;
  color?: unknown;
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
}
```
