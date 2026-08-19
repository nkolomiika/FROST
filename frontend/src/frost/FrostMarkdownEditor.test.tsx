import { render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";

import { FrostMarkdownEditor } from "./FrostMarkdownEditor";

/* The point of this editor is that markdown renders in place while typing —
   "### " turns the line into a real <h3> in the same line, no preview pane. That
   comes from TipTap's StarterKit input rules, so these tests exercise the real
   editor rather than mocking it. */

const Harness = ({ initial = "" }: { initial?: string }) => {
  const [value, setValue] = useState(initial);
  return (
    <div className="frost">
      <FrostMarkdownEditor value={value} onChange={setValue} placeholder="Write your note…" />
      <span data-testid="markdown">{value}</span>
    </div>
  );
};

/** Types into the ProseMirror surface the way input rules see it. */
const typeInto = async (el: HTMLElement, text: string) => {
  const { default: userEvent } = await import("@testing-library/user-event");
  const user = userEvent.setup();
  await user.click(el);
  await user.keyboard(text);
};

describe("FrostMarkdownEditor", () => {
  it("renders existing markdown as formatted content, not as source text", async () => {
    render(<Harness initial={"# Заголовок\n\nабзац\n\n- пункт"} />);
    await waitFor(() => expect(document.querySelector(".frostmd-input h1")).toBeInTheDocument());
    expect(document.querySelector(".frostmd-input h1")).toHaveTextContent("Заголовок");
    expect(document.querySelector(".frostmd-input li")).toHaveTextContent("пункт");
    // The markup itself is never shown as literal text.
    expect(screen.queryByText("# Заголовок")).not.toBeInTheDocument();
  });

  it("turns '### ' into a heading in place as it is typed", async () => {
    render(<Harness />);
    const surface = document.querySelector(".frostmd-input") as HTMLElement;
    await typeInto(surface, "### Recon");

    await waitFor(() => expect(document.querySelector(".frostmd-input h3")).toBeInTheDocument());
    const h3 = document.querySelector(".frostmd-input h3") as HTMLElement;
    // The "### " is consumed by the input rule — the heading holds only the text.
    expect(h3).toHaveTextContent("Recon");
    expect(h3.textContent).not.toContain("#");
  });

  it("keeps the value as markdown so notes stay markdown in the database", async () => {
    render(<Harness />);
    const surface = document.querySelector(".frostmd-input") as HTMLElement;
    await typeInto(surface, "### Recon");

    await waitFor(() => expect(screen.getByTestId("markdown")).toHaveTextContent("### Recon"));
  });

  it("turns '- ' into a list item", async () => {
    render(<Harness />);
    const surface = document.querySelector(".frostmd-input") as HTMLElement;
    await typeInto(surface, "- первый");

    await waitFor(() => expect(document.querySelector(".frostmd-input ul li")).toBeInTheDocument());
    expect(screen.getByTestId("markdown")).toHaveTextContent("- первый");
  });
});
