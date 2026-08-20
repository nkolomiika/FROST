/* FROST brand marks for the app chrome.
 *  · FrostMark      — the B6 crystal (diamond) icon, used as the logo glyph.
 *  · FrostWordmark  — the wordmark with a crystalline first letter F.
 * Colours come from the app's --fr-* accent tokens, so the marks track the theme. */

/** The faceted crystal (logo mark), sized in px. Decorative — hidden from a11y tree. */
export function FrostMark({ size = 24, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 120 120" className={className} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="frDiamond" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="var(--fr-cyan)" />
          <stop offset=".6" stopColor="var(--fr-accent)" />
          <stop offset="1" stopColor="var(--fr-accent)" />
        </linearGradient>
      </defs>
      <polygon points="60,10 110,60 60,110 10,60" fill="url(#frDiamond)" />
      <polygon points="60,10 110,60 60,60" fill="#ffffff" fillOpacity=".22" />
      <polygon points="10,60 60,10 60,60" fill="#ffffff" fillOpacity=".08" />
      <polygon points="110,60 60,110 60,60" fill="#000000" fillOpacity=".18" />
      <polygon points="10,60 60,110 60,60" fill="#000000" fillOpacity=".08" />
      <g stroke="#ffffff" strokeOpacity=".9" strokeWidth="2.4" strokeLinecap="round">
        <line x1="60" y1="44" x2="60" y2="76" />
        <line x1="44" y1="60" x2="76" y2="60" />
      </g>
    </svg>
  );
}

/** The FROST wordmark; the leading F carries the crystal gradient (see frost.css). */
export function FrostWordmark({ size = 16, spacing = 3 }: { size?: number; spacing?: number }) {
  return (
    <span className="fr-wm" style={{ fontSize: size, letterSpacing: spacing }}>
      <span className="fr-wm-f">F</span>ROST
    </span>
  );
}
