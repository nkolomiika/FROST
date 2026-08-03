var __dsPreview = (() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __esm = (fn, res, err) => function __init() {
    if (err) throw err[0];
    try {
      return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
    } catch (e) {
      throw err = [e], e;
    }
  };
  var __commonJS = (cb, mod) => function __require() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));
  var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

  // <define:import.meta.env>
  var init_define_import_meta_env = __esm({
    "<define:import.meta.env>"() {
    }
  });

  // ds-raw:__ds_raw__
  var require_ds_raw = __commonJS({
    "ds-raw:__ds_raw__"(exports, module) {
      init_define_import_meta_env();
      module.exports = window.SberDesignKit;
    }
  });

  // shim:react-shim
  var require_react_shim = __commonJS({
    "shim:react-shim"(exports, module) {
      init_define_import_meta_env();
      var R = window.React;
      function jsx2(t, p, k) {
        return R.createElement(t, k === void 0 ? p : Object.assign({ key: k }, p));
      }
      module.exports = R;
      module.exports.jsx = jsx2;
      module.exports.jsxs = jsx2;
      module.exports.jsxDEV = jsx2;
      module.exports.Fragment = R.Fragment;
    }
  });

  // .design-sync/previews/Card.tsx
  var Card_exports = {};
  __export(Card_exports, {
    Basic: () => Basic,
    ProjectCard: () => ProjectCard,
    VulnerabilityCard: () => VulnerabilityCard
  });
  init_define_import_meta_env();

  // ds-shim:ds
  var ds_exports = {};
  __export(ds_exports, {
    default: () => ds_default
  });
  init_define_import_meta_env();
  __reExport(ds_exports, __toESM(require_ds_raw()));
  var g = window.SberDesignKit;
  var ds_default = "default" in g ? g.default : g;

  // .design-sync/previews/Card.tsx
  var import_jsx_runtime = __toESM(require_react_shim());
  function VulnerabilityCard() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Card, { sx: { maxWidth: 420 }, children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.CardContent, { children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.Stack, { direction: "row", justifyContent: "space-between", alignItems: "flex-start", spacing: 2, children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Typography, { variant: "h6", children: "SQL Injection in /api/v2/hosts" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Chip, { label: "High", color: "error", size: "small" })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.Typography, { variant: "body2", color: "text.secondary", sx: { mt: 1 }, children: [
        "User-supplied ",
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)("code", { children: "filter" }),
        " parameter is concatenated into a raw SQL query, allowing extraction of arbitrary table contents."
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Divider, { sx: { my: 2 } }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.Stack, { direction: "row", spacing: 1, flexWrap: "wrap", children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Chip, { label: "CVSS 8.6", size: "small", variant: "outlined" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Chip, { label: "CWE-89", size: "small", variant: "outlined" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Chip, { label: "10.0.14.7", size: "small", variant: "outlined" })
      ] })
    ] }) });
  }
  function ProjectCard() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Card, { sx: { maxWidth: 420 }, children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.CardContent, { children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Typography, { variant: "subtitle1", children: "Acme Corp — External Pentest" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Typography, { variant: "body2", color: "text.secondary", sx: { mt: 0.5 }, children: "12 hosts · 38 findings · ends 2026-07-15" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.Stack, { direction: "row", spacing: 1, sx: { mt: 2 }, children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Chip, { label: "Critical: 2", color: "error", size: "small" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Chip, { label: "High: 9", color: "warning", size: "small" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Chip, { label: "Medium: 14", size: "small", variant: "outlined" })
      ] }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.Box, { sx: { display: "flex", justifyContent: "flex-end", gap: 1, mt: 2 }, children: [
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Button, { size: "small", variant: "text", children: "Archive" }),
        /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Button, { size: "small", variant: "contained", children: "Open" })
      ] })
    ] }) });
  }
  function Basic() {
    return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Card, { sx: { maxWidth: 420 }, children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)(ds_exports.CardContent, { children: [
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Typography, { variant: "h6", children: "Scan settings" }),
      /* @__PURE__ */ (0, import_jsx_runtime.jsx)(ds_exports.Typography, { variant: "body2", color: "text.secondary", sx: { mt: 1 }, children: "Cards use a flat, zero-radius surface with a faint cyan border and no shadow — the defining geometry of the SberPCF theme." })
    ] }) });
  }
  return __toCommonJS(Card_exports);
})();
