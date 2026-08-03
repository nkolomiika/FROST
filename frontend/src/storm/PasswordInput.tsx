/* Password input in the STORM design language with a built-in reveal toggle.
   Frame is the shared .finp field; the eye button flips type between password
   and text. Used on the sign-in and registration screens. */

import { useState, type CSSProperties } from "react";
import "./storm.css";
import { Icon } from "./icons";

interface PasswordInputProps {
  id?: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  autoComplete?: string;
  autoFocus?: boolean;
  style?: CSSProperties;
}

export function PasswordInput({ id, value, onChange, placeholder, autoComplete, autoFocus, style }: PasswordInputProps) {
  const [show, setShow] = useState(false);
  return (
    <div style={{ position: "relative" }}>
      <input
        id={id}
        className="finp"
        type={show ? "text" : "password"}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{ paddingRight: 42, ...style }}
      />
      <button
        type="button"
        className="clk"
        onClick={() => setShow((s) => !s)}
        aria-label={show ? "Hide password" : "Show password"}
        title={show ? "Hide password" : "Show password"}
        style={{ position: "absolute", top: 0, right: 0, height: "100%", width: 42, display: "flex", alignItems: "center", justifyContent: "center", background: "transparent", border: "none", color: "var(--st-text-faint)", cursor: "pointer", padding: 0 }}
      >
        <Icon name={show ? "eye-off" : "eye"} size={18} />
      </button>
    </div>
  );
}
