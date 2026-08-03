import { render, screen, fireEvent } from "@testing-library/react";
import { StormDocs } from "./StormDocs";

describe("StormDocs — раздел /docs", () => {
  it("лендинг: заголовок Docs и карточки категорий по роли (обычный пользователь)", () => {
    render(<StormDocs isAdmin={false} />);
    // раздел называется Docs (в шапке сайдбара и в заголовке лендинга)
    expect(screen.getAllByText("Docs").length).toBeGreaterThan(0);
    // документы «Пользователь» и «Agent API» видны, «Администратор» — нет (скрытие)
    expect(screen.getAllByText("Пользователь").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Agent API").length).toBeGreaterThan(0);
    expect(screen.queryByText("Администратор")).toBeNull();
  });

  it("администратор дополнительно видит документ «Администратор»", () => {
    render(<StormDocs isAdmin={true} />);
    expect(screen.getAllByText("Администратор").length).toBeGreaterThan(0);
  });

  it("клик по главе в дереве открывает её (лендинг сменяется контентом)", () => {
    render(<StormDocs isAdmin={false} />);
    // до клика заголовок главы есть только в дереве
    expect(screen.getAllByText("Начало работы").length).toBe(1);
    fireEvent.click(screen.getByText("Начало работы"));
    // после — глава отрисовалась (дерево + крошки + markdown)
    expect(screen.getAllByText("Начало работы").length).toBeGreaterThan(1);
  });

  it("поиск фильтрует дерево и показывает результаты", () => {
    render(<StormDocs isAdmin={false} />);
    fireEvent.change(screen.getByPlaceholderText("Поиск по Docs…"), { target: { value: "уязвим" } });
    expect(screen.getByText("Результаты поиска")).toBeTruthy();
    expect(screen.getAllByText("Уязвимости").length).toBeGreaterThan(0);
  });
});
