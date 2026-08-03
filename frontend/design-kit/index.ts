/**
 * SberPCF Design Kit
 *
 * The themed building blocks of the SberPCF web application: the real MUI v6
 * components the product is built from, branded by the SberPCF dark theme, plus
 * the theme itself and the root provider that applies it.
 *
 * This is not a reimplementation — every component is the genuine `@mui/material`
 * export. The SberPCF look comes entirely from `sberTheme` / `SberThemeProvider`.
 */

// Theme + root provider — the source of all branding.
export { SberThemeProvider } from "./SberThemeProvider";
export type { SberThemeProviderProps } from "./SberThemeProvider";
export { sberTheme, createAppTheme } from "./theme";

// Themed MUI primitives the SberPCF design system builds with.
export {
  Alert,
  AppBar,
  Autocomplete,
  Avatar,
  Badge,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  CircularProgress,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  FormControlLabel,
  FormGroup,
  Grid2 as Grid,
  IconButton,
  InputAdornment,
  InputLabel,
  LinearProgress,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  OutlinedInput,
  Pagination,
  Paper,
  Popover,
  Select,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Toolbar,
  Tooltip,
  Typography,
} from "@mui/material";
