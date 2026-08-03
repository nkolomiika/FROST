import { defaultUrlTransform, type UrlTransform } from "react-markdown";

const SAFE_IMAGE_DATA_URL_RE = /^data:image\/(png|jpe?g|gif|webp|avif|bmp);base64,[A-Za-z0-9+/=]+$/i;

/**
 * Разрешает data:image (вставка картинок в Markdown) и ведёт себя как {@link defaultUrlTransform} для остальных URL.
 * Whitelist: только base64-кодированные image/* с известными типами. data:text/html и любые иные mime отсекаются.
 */
export const markdownUrlTransform: UrlTransform = (url) => {
  const trimmed = url.trim();
  if (trimmed.toLowerCase().startsWith("data:")) {
    return SAFE_IMAGE_DATA_URL_RE.test(trimmed) ? trimmed : "";
  }
  return defaultUrlTransform(trimmed);
};

const MARKDOWN_IMAGE_BLOCK_RE = /!\[[^\]]*\]\([^)\s]+(?:\s+"[^"]*")?\)/g;

/**
 * Нормализует markdown перед рендером: каждая markdown-картинка должна быть
 * отделена от соседнего текста пустой строкой, иначе react-markdown склеит их
 * в один абзац (картинка окажется на одной строке с текстом).
 *
 * Используется как для просмотра, так и для legacy-данных, у которых при
 * сохранении не было `\n\n` вокруг картинок.
 */
export const normalizeMarkdownForRender = (value: string | null | undefined): string => {
  if (!value) {
    return "";
  }
  let normalized = value.replace(/\r\n/g, "\n");
  normalized = normalized.replace(
    new RegExp(`([^\\n])\\n?(${MARKDOWN_IMAGE_BLOCK_RE.source})`, "g"),
    "$1\n\n$2"
  );
  normalized = normalized.replace(
    new RegExp(`(${MARKDOWN_IMAGE_BLOCK_RE.source})\\n?(?!\\n|!\\[|$)`, "g"),
    "$1\n\n"
  );
  return normalized.replace(/\n{3,}/g, "\n\n");
};
