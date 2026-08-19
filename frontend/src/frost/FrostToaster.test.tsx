import { fireEvent, render, screen } from "@testing-library/react";
import { act } from "react";
import { FrostToaster } from "./FrostToaster";
import { useToastStore } from "../store";

describe("FrostToaster", () => {
  beforeEach(() => {
    useToastStore.setState({ toasts: [], nextId: 1 });
  });

  it("renders a pushed toast and dismisses it on close", () => {
    render(<FrostToaster />);
    expect(screen.queryByText("Сервер недоступен")).not.toBeInTheDocument();

    act(() => {
      useToastStore.getState().pushToast("Сервер недоступен", "error");
    });
    expect(screen.getByText("Сервер недоступен")).toBeInTheDocument();

    // The close (×) button is the only actbtn in the toast.
    fireEvent.click(document.querySelector(".actbtn") as HTMLElement);
    expect(screen.queryByText("Сервер недоступен")).not.toBeInTheDocument();
  });
});
