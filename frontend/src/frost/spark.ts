/* Sparkline geometry helpers — pure functions returning SVG point strings. */

/** Deterministic sparkline point string from a seed. */
export function sparkline(seed: number, current: number): string {
  const n = 6;
  const w = 74;
  const h = 30;
  const pad = 3;
  const vals: number[] = [];
  let v = Math.max(0, current - (2 + (seed % 4)));
  for (let i = 0; i < n - 1; i++) {
    v = Math.max(0, v + (((seed * (i + 3)) % 5) - 2));
    vals.push(v);
  }
  vals.push(current);
  const max = Math.max(1, ...vals);
  const stepX = w / (n - 1);
  return vals.map((val, i) => `${Math.round(i * stepX)},${Math.round(h - pad - (val / max) * (h - pad * 2))}`).join(" ");
}

/**
 * Cumulative-count sparkline driven by real "added at" timestamps.
 *
 * X is the engagement window [start, end]; the line is drawn only up to today,
 * so an unfinished project stops partway across the card. Y is the running
 * number of entities created at or before each sampled instant — every add
 * pushes the line up, and a burst of adds shows as a steeper climb.
 *
 * `startMs`/`endMs` are epoch millis (NaN when the project has no dates set); we
 * then fall back to the entities' own first/last timestamps so the card still
 * renders something meaningful.
 */
export function cumulativeSpark(
  timestamps: (string | null | undefined)[],
  startMs: number,
  endMs: number,
  w = 111,
  h = 30,
  pad = 3,
): string {
  const now = Date.now();
  const times = timestamps
    .map((t) => Date.parse(t ?? ""))
    .filter((t) => Number.isFinite(t))
    .sort((a, b) => a - b);

  let start = startMs;
  let end = endMs;
  if (!Number.isFinite(start)) start = times.length ? times[0] : now - 7 * 864e5;
  if (!Number.isFinite(end) || end <= start) {
    end = Math.max(now, times.length ? times[times.length - 1] : now, start + 864e5);
  }

  /* Ось X — прошедшая часть окна: от старта до «сегодня», но не дальше конца
     проекта. Нормируем именно по ней (а не по всему start…end), иначе у активного
     проекта линия обрывалась бы на середине карточки, и спарклайны в соседних
     виджетах получались бы разной длины. */
  const cutoff = Math.max(start + 1, Math.min(now, end));
  const span = cutoff - start;
  const maxY = Math.max(1, times.length);
  const yTop = pad;
  const yBot = h - pad;
  const N = 16;

  const pts: string[] = [];
  for (let i = 0; i < N; i++) {
    const t = start + ((cutoff - start) * i) / (N - 1);
    let count = 0;
    for (const ts of times) {
      if (ts <= t) count++;
      else break;
    }
    const x = (w * (t - start)) / span;
    const y = yBot - (count / maxY) * (yBot - yTop);
    pts.push(`${Math.round(x)},${Math.round(y)}`);
  }
  return pts.join(" ");
}

/** Замыкает спарклайн вниз до базовой линии — заливка того же цвета под графиком. */
export function sparkArea(points: string, w: number, h = 30): string {
  if (!points) return "";
  return `0,${h} ${points} ${w},${h}`;
}
