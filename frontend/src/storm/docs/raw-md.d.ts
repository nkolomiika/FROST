// Vite `?raw` imports resolve to the file's text content. Declared here because
// tsconfig restricts `types` to vitest/globals, so vite/client's ambient module
// declarations aren't pulled in automatically.
declare module "*?raw" {
  const content: string;
  export default content;
}
