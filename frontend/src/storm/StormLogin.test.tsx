import { fireEvent, render, screen } from "@testing-library/react";
import { vi } from "vitest";
import { StormLogin } from "./StormLogin";
import { useAuthStore } from "../store";

describe("StormLogin", () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, error: null, isLoading: false });
  });

  it("renders the STORM sign-in form", () => {
    render(<StormLogin />);
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });

  it("enables submit only when both fields are filled", () => {
    render(<StormLogin />);
    const btn = screen.getByRole("button", { name: /Sign in/i });
    expect(btn).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "m.antonov" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
    expect(btn).not.toBeDisabled();
  });

  it("switches to the 2FA code step when the backend requires it", async () => {
    const signIn = vi.fn().mockResolvedValue({ status: "2fa_required" });
    useAuthStore.setState({ signIn });
    render(<StormLogin />);
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "admin" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "admin" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    expect(await screen.findByRole("heading", { name: "Two-factor code" })).toBeInTheDocument();
    expect(screen.getByLabelText("Authentication code")).toBeInTheDocument();
  });
});
