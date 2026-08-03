Tooltip from sberpcf-design-kit. Use via `window.SberDesignKit.Tooltip` (bundle loaded from the root `_ds_bundle.js`). Wrap the tree in `<SberThemeProvider>` (full provider chain in README.md — components read theme/i18n from that context).

## Props

```ts
interface TooltipProps {
  /** If `true`, adds an arrow to the tooltip. */
  arrow?: boolean;
  /** Tooltip reference element. */
  children: React.ReactElement<unknown, any>;
  /** Override or extend the styles applied to the component. */
  classes?: Partial<TooltipClasses>;
  /** The components used for each slot inside. */
  components?: { Popper?: React.ElementType<PopperProps>; Transition?: React.ElementType; Tooltip?: React.ElementType; Arrow?: React.ElementType; };
  /** The extra props for the slot components. You can override the existing props or add new ones. */
  componentsProps?: unknown;
  /** Set to `true` if the `title` acts as an accessible description. By default the `title` acts as an accessible label for t */
  describeChild?: boolean;
  /** Do not respond to focus-visible events. */
  disableFocusListener?: boolean;
  /** Do not respond to hover events. */
  disableHoverListener?: boolean;
  /** Makes a tooltip not interactive, i.e. it will close when the user hovers over the tooltip before the `leaveDelay` is exp */
  disableInteractive?: boolean;
  /** Do not respond to long press touch events. */
  disableTouchListener?: boolean;
  /** The number of milliseconds to wait before showing the tooltip. This prop won't impact the enter touch delay (`enterTouch */
  enterDelay?: number;
  /** The number of milliseconds to wait before showing the tooltip when one was already recently opened. */
  enterNextDelay?: number;
  /** The number of milliseconds a user must touch the element before showing the tooltip. */
  enterTouchDelay?: number;
  /** If `true`, the tooltip follow the cursor over the wrapped element. */
  followCursor?: boolean;
  /** This prop is used to help implement the accessibility logic. If you don't provide this prop. It falls back to a randomly */
  id?: string;
  /** The number of milliseconds to wait before hiding the tooltip. This prop won't impact the leave touch delay (`leaveTouchD */
  leaveDelay?: number;
  /** The number of milliseconds after the user stops touching an element before hiding the tooltip. */
  leaveTouchDelay?: number;
  /** If `true`, the component is shown. */
  open?: boolean;
  /** Tooltip placement. */
  placement?: "bottom" | "left" | "right" | "top" | "auto" | "auto-start" | "auto-end" | "top-start" | "top-end" | "bottom-start" | "bottom-end" | "right-start" | "right-end" | "left-start" | "left-end";
  /** The component used for the popper. */
  PopperComponent?: ((props: PopperProps, deprecatedLegacyContext?: any) => React.ReactNode) | (new (props: PopperProps, deprecatedLegacyContext?: any) => React.Component<any, any>);
  /** Props applied to the [`Popper`](https://mui.com/material-ui/api/popper/) element. */
  PopperProps?: Partial<PopperProps>;
  /** The system prop that allows defining system overrides as well as additional CSS styles. */
  sx?: unknown;
  /** Tooltip title. Zero-length titles string, undefined, null and false are never displayed. */
  title: React.ReactNode;
  /** The component used for the transition. [Follow this guide](https://mui.com/material-ui/transitions/#transitioncomponent- */
  TransitionComponent?: unknown;
  /** Props applied to the transition element. By default, the element is based on this [`Transition`](https://reactcommunity. */
  TransitionProps?: TransitionProps;
  className?: string;
  style?: React.CSSProperties;
  ref?: React.Ref;
  /** The components used for each slot inside. */
  slots?: Partial<TooltipSlots>;
  /** The props used for each slot inside. */
  slotProps?: unknown;
}
```
