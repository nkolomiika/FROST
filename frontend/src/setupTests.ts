import "@testing-library/jest-dom/vitest";

if (!window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

if (!window.ResizeObserver) {
  class ResizeObserverMock {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  Object.defineProperty(window, "ResizeObserver", {
    writable: true,
    value: ResizeObserverMock,
  });
}

/* jsdom has no layout engine, but ProseMirror (the TipTap note editor) asks the
   DOM where things are on screen. Without these it throws inside event handling
   and the editor never processes input. Empty rectangles are enough: the tests
   assert on the document, not on geometry. */
const EMPTY_RECT: DOMRect = {
  x: 0, y: 0, top: 0, left: 0, bottom: 0, right: 0, width: 0, height: 0,
  toJSON: () => ({}),
};
const emptyRectList = (): DOMRectList =>
  Object.assign([] as unknown as DOMRectList, { item: () => null, length: 0 });

if (!Range.prototype.getClientRects) {
  Range.prototype.getClientRects = emptyRectList;
  Range.prototype.getBoundingClientRect = () => EMPTY_RECT;
}
if (!Element.prototype.getClientRects || Element.prototype.getClientRects.call(document.body).length === 0) {
  Element.prototype.getClientRects = emptyRectList;
}
if (!document.elementFromPoint) {
  document.elementFromPoint = () => null;
}
