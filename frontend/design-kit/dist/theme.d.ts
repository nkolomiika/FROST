import { type PaletteMode, type Theme } from "@mui/material";
/**
 * Builds the SberPCF application theme.
 *
 * This is the single source of the design language: the dark palette, the
 * zero-radius geometry, Inter typography, and the per-component MUI style
 * overrides that brand every primitive. It is extracted verbatim from the
 * application's runtime theme (`frontend/src/main.tsx`) so the design kit and
 * the shipping app stay visually identical.
 */
export declare function createAppTheme(mode?: PaletteMode): Theme;
/** The default SberPCF dark theme instance. */
export declare const sberTheme: Theme;
