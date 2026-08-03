import * as React from 'react';

/**
 * Avatar — from sberpcf-design-kit@1.0.0.
 */
export interface AvatarProps {
  /** The component used for the root node. Either a string to use a HTML element or a component. */
  component: RootComponent;
  /** Used in combination with `src` or `srcSet` to provide an alt attribute for the rendered `img` element. */
  alt?: string;
  /** Used to render icon or text elements inside the Avatar if `src` is not set. This can be an element, or just a string. */
  children?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<AvatarClasses> & Partial<ClassNameMap<never>>;
  /** [Attributes](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/img#attributes) applied to the `img` element if t */
  imgProps?: React.ImgHTMLAttributes<HTMLImageElement> & { sx?: SxProps<Theme>; };
  /** The `sizes` attribute for the `img` element. */
  sizes?: string;
  /** The `src` attribute for the `img` element. */
  src?: string;
  /** The `srcSet` attribute for the `img` element. Use this attribute for responsive image display. */
  srcSet?: string;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The shape of the avatar. */
  variant?: "square" | "circular" | "rounded";
  /** The components used for each slot inside. */
  slots?: Partial<AvatarSlots>;
  /** The props used for each slot inside. */
  slotProps?: { img?: SlotProps<React.ElementType<React.ImgHTMLAttributes<HTMLImageElement>>, {}, AvatarOwnProps>; };
  className?: string;
  style?: React.CSSProperties;
}

export declare const Avatar: React.ComponentType<AvatarProps>;
