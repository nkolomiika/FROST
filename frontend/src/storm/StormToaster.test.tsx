import { fireEvent, render, screen } from "@testing-library/react";
import { act } from "react";
import { StormToaster } from "./StormToaster";
import { useToastStore } from "../store";

describe("StormToaster", () => {
  beforeEach(() => {
    useToastStore.setState({ toasts: [], nextId: 1 });
  });

  it("renders a pushed toast and dismisses it on close", () => {
    render(<StormToaster />);
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
