import * as React from 'react';

/**
 * Checkbox — from sberpcf-design-kit@1.0.0.
 * @replaces input[type=checkbox]
 */
export interface CheckboxProps {
  /** If `true`, the component is checked. */
  checked?: boolean;
  /** The icon to display when the component is checked. */
  checkedIcon?: React.ReactNode;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<CheckboxClasses>;
  /** The color of the component. It supports both default and custom theme colors, which can be added as shown in the [palett */
  color?: "success" | "info" | "warning" | "error" | "default" | "primary" | "secondary";
  /** If `true`, the component is disabled. */
  disabled?: boolean;
  /** If `true`, the ripple effect is disabled. */
  disableRipple?: boolean;
  /** The icon to display when the component is unchecked. */
  icon?: React.ReactNode;
  /** The id of the `input` element. */
  id?: string;
  /** If `true`, the component appears indeterminate. This does not set the native input element to indeterminate due to incon */
  indeterminate?: boolean;
  /** The icon to display when the component is indeterminate. */
  indeterminateIcon?: React.ReactNode;
  /** If `true`, the `input` element is required. */
  required?: boolean;
  /** The size of the component. `small` is equivalent to the dense checkbox styling. */
  size?: "small" | "large" | "medium";
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The value of the component. The DOM API casts this to a string. The browser uses "on" as the default value. */
  value?: unknown;
  className?: string;
  style?: React.CSSProperties;
  ref?: React.Ref;
  /** The default checked state. Use when the component is not controlled. */
  defaultChecked?: boolean;
  autoFocus?: boolean;
  tabIndex?: number;
  component?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** A ref for imperative actions. It currently only supports `focusVisible()` action. */
  action?: React.Ref;
  /** If `true`, the ripples are centered. They won't start at the cursor interaction position. */
  centerRipple?: boolean;
  /** If `true`, the touch ripple effect is disabled. */
  disableTouchRipple?: boolean;
  /** If `true`, the base button will have a keyboard focus ripple. */
  focusRipple?: boolean;
  /** This prop can help identify which element has keyboard focus. The class name will be applied when the element gains the  */
  focusVisibleClassName?: string;
  /** The component used to render a link when the `href` prop is provided. */
  LinkComponent?: "symbol" | "object" | "header" | "div" | "span" | "button" | "hr" | "label" | "ul" | "li" | "table" | "tbody" | "thead" | "tr" | "style" | "a" | (string & {}) /* +164 more */;
  /** Props applied to the `TouchRipple` element. */
  TouchRippleProps?: Partial<TouchRippleProps>;
  /** A ref that points to the `TouchRipple` element. */
  touchRippleRef?: React.Ref;
  /** If `true`, the keyboard focus ripple is disabled. */
  disableFocusRipple?: boolean;
  /** If given, uses a negative margin to counteract the padding on one side (this is often helpful for aligning the left or r */
  edge?: false | "end" | "start";
  /** Name attribute of the `input` element. */
  name?: string;
  readOnly?: boolean;
  /** [Attributes](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input#Attributes) applied to the `input` element. */
  inputProps?: React.InputHTMLAttributes<HTMLInputElement>;
  /** Pass a ref to the `input` element. */
  inputRef?: React.Ref;
  /** The components used for each slot inside. */
  slots?: Partial<CheckboxSlots>;
  /** The props used for each slot inside. */
  slotProps?: { root?: SlotProps<React.ElementType<SwitchBaseProps>, CheckboxRootSlotPropsOverrides, CheckboxOwnerState>; input?: SlotProps<"input", CheckboxInputSlotPropsOverrides, CheckboxOwnerState>; };
}

export declare const Checkbox: React.ComponentType<CheckboxProps>;
