import * as React from 'react';

/**
 * Stack — from sberpcf-design-kit@1.0.0.
 */
export interface StackProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** The content of the component. */
  children?: React.ReactNode;
  /** Defines the `flex-direction` style property. It is applied for all screen sizes. */
  direction?: "row" | "column" | "column-reverse" | "row-reverse" | ("row" | "column" | "column-reverse" | "row-reverse")[] | { [key: string]: "row" | "column" | "column-reverse" | "row-reverse"; };
  /** Defines the space between immediate children. */
  spacing?: string | number | (string | number)[] | { [key: string]: string | number; };
  /** Add an element between each child. */
  divider?: React.ReactNode;
  /** If `true`, the CSS flexbox `gap` is used instead of applying `margin` to children. While CSS `gap` removes the [known li */
  useFlexGap?: boolean;
  /** The system prop, which allows defining system overrides as well as additional CSS styles. */
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
  className?: string;
  style?: React.CSSProperties;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<ClassNameMap<never>>;
}

export declare const Stack: React.ComponentType<StackProps>;
