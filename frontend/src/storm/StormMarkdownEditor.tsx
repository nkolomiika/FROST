/* Live Markdown editor for Storm notes.
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
 * dark UI; this one is plain-DOM and styled through storm.css, because Storm
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
}

/** tiptap-markdown hangs its serialiser off the editor's storage. */
const getMarkdown = (storage: unknown): string =>
  (storage as { markdown?: { getMarkdown: () => string } }).markdown?.getMarkdown() ?? "";

export function StormMarkdownEditor({ value, onChange, placeholder = "", minHeight = 260 }: Props) {
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
    editorProps: { attributes: { class: "stormmd-input", spellcheck: "true" } },
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
    <div className="stormmd" style={{ minHeight }} onClick={() => editor?.chain().focus().run()}>
      <EditorContent editor={editor} />
    </div>
  );
}

export default StormMarkdownEditor;
