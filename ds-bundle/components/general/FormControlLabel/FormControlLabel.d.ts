import * as React from 'react';

/**
 * FormControlLabel — from sberpcf-design-kit@1.0.0.
 */
export interface FormControlLabelProps {
  /** If `true`, the component appears selected. */
  checked?: boolean;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<FormControlLabelClasses>;
  /** The props used for each slot inside. */
  componentsProps?: { typography?: TypographyProps; };
  /** A control element. For instance, it can be a `Radio`, a `Switch` or a `Checkbox`. */
  control: React.ReactElement<unknown, any>;
  /** If `true`, the control is disabled. */
  disabled?: boolean;
  /** If `true`, the label is rendered as it is passed without an additional typography node. */
  disableTypography?: boolean;
  /** Pass a ref to the `input` element. */
  inputRef?: React.Ref;
  /** A text or an element to be used in an enclosing label element. */
  label: React.ReactNode;
  /** The position of the label. */
  labelPlacement?: "bottom" | "top" | "end" | "start";
  name?: string;
  /** If `true`, the label will indicate that the `input` is required. */
  required?: boolean;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** The value of the component. */
  value?: unknown;
  className?: string;
  style?: React.CSSProperties;
  id?: string;
  ref?: React.Ref;
  /** The components used for each slot inside. */
  slots?: Partial<FormControlLabelSlots>;
  /** The props used for each slot inside. */
  slotProps?: { typography?: SlotProps<typeof Typography, {}, FormControlLabelProps>; };
}

export declare const FormControlLabel: React.ComponentType<FormControlLabelProps>;
