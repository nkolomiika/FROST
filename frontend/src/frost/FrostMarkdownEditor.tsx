/* Live Markdown editor for Frost notes.
 *
 * Notion-style: the text renders as you type, in place — typing "### " turns the
 * line into a heading right there, with no preview pane and no second surface.
 * That behaviour is TipTap's StarterKit input rules; nothing here implements it.
 *
 * Notes are stored as Markdown (ProjectNote.content) and read back by the viewer
 * and the Word reports, so the editor keeps Markdown as its value format via
 * tiptap-markdown rather than exposing HTML.
 *
 * The MUI twin in ../components/MarkdownEditor.tsx does the same for the old
 * dark UI; this one is plain-DOM and styled through frost.css, because Frost
 * does not use MUI.
 */
import { useEffect, useMemo, useRef } from "react";
import { EditorContent, useEditor } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import Link from "@tiptap/extension-link";
import Placeholder from "@tiptap/extension-placeholder";
import { Markdown } from "tiptap-markdown";

interface Props {
  value: string;
  onChange: (markdown: string) => void;
  placeholder?: string;
  minHeight?: number;
  /** When set, pasted image files are handed off here (and NOT inserted into the
      document) instead of being dropped — used by the step editor to attach
      screenshots. Returning nothing; the caller decides what to do with them. */
  onImagePaste?: (files: File[]) => void;
}

/** tiptap-markdown hangs its serialiser off the editor's storage. */
const getMarkdown = (storage: unknown): string =>
  (storage as { markdown?: { getMarkdown: () => string } }).markdown?.getMarkdown() ?? "";

export function FrostMarkdownEditor({ value, onChange, placeholder = "", minHeight = 260, onImagePaste }: Props) {
  /* onImagePaste can change identity between renders; keep the latest in a ref so
     the editor's paste handler (created once) always calls the current one. */
  const onImagePasteRef = useRef(onImagePaste);
  onImagePasteRef.current = onImagePaste;
  /* The last Markdown we emitted or applied. Without it the two syncs below
     fight: onUpdate pushes a value up, the prop comes back down, setContent
     resets the document and the caret jumps to the start on every keystroke. */
  const lastSyncedRef = useRef<string>(value);

  const editor = useEditor({
    extensions: useMemo(
      () => [
        // The markdown shortcuts (### space, - space, > space, **bold**, ``` …)
        // are StarterKit's own input rules — that is the whole feature.
        StarterKit.configure({ heading: { levels: [1, 2, 3, 4, 5, 6] } }),
        Link.configure({ openOnClick: false, autolink: true, HTMLAttributes: { rel: "noopener noreferrer", target: "_blank" } }),
        Placeholder.configure({ placeholder }),
        Markdown.configure({
          html: false,
          tightLists: true,
          bulletListMarker: "-",
          linkify: true,
          breaks: true,
          transformPastedText: true,
          transformCopiedText: true,
        }),
      ],
      [placeholder]
    ),
    content: value,
    editorProps: {
      attributes: { class: "frostmd-input", spellcheck: "true" },
      // Intercept pasted images: hand the files to the caller and swallow the
      // paste so TipTap doesn't try to inline them. Text pastes fall through.
      handlePaste: (_view, event) => {
        const cb = onImagePasteRef.current;
        if (!cb) return false;
        const files = Array.from(event.clipboardData?.files ?? []).filter((f) => f.type.startsWith("image/"));
        if (files.length === 0) return false;
        event.preventDefault();
        cb(files);
        return true;
      },
    },
    onUpdate: ({ editor: ed }) => {
      const md = getMarkdown(ed.storage);
      lastSyncedRef.current = md;
      onChange(md);
    },
  });

  // The value changed from the outside (a note finished loading, editor reopened).
  useEffect(() => {
    if (!editor || value === lastSyncedRef.current) return;
    lastSyncedRef.current = value;
    editor.commands.setContent(value, false);
  }, [value, editor]);

  return (
    <div className="frostmd" style={{ minHeight }} onClick={() => editor?.chain().focus().run()}>
      <EditorContent editor={editor} />
    </div>
  );
}

export default FrostMarkdownEditor;
