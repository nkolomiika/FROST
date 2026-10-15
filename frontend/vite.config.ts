import basicSsl from "@vitejs/plugin-basic-ssl";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const proxyTarget = process.env.VITE_PROXY_TARGET ?? "http://backend:8000";

/**
 * Некоторые браузерные расширения (напр. AWS-инструменты) без спроса запрашивают
 * `/aws-exports.js` в корне сайта. Vite dev-сервер пытается прочитать такой файл
 * с диска, падает с ENOENT и показывает error-overlay поверх приложения, хотя в
 * коде FROST этого файла нет и не должно быть. Отдаём пустой модуль, чтобы запрос
 * тихо завершался и не ломал разработку.
 */
function ignoreAwsExports(): Plugin {
  return {
    name: "frost:ignore-aws-exports",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url?.split("?")[0];
        if (url === "/aws-exports.js") {
          res.statusCode = 200;
          res.setHeader("Content-Type", "text/javascript");
          res.end("export {};\n");
          return;
        }
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [ignoreAwsExports(), react(), basicSsl()],
  resolve: {
    extensions: [".ts", ".tsx", ".js", ".jsx", ".mjs", ".json"],
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/setupTests.ts",
    /** Дубликаты компилированных *.test.js рядом с *.test.tsx давали двойной запуск одних и тех же тестов. */
    exclude: ["**/node_modules/**", "**/dist/**", "**/*.test.js"],
  },
  server: {
    host: "0.0.0.0",
    port: 3000,
    https: true,
    proxy: {
      "/api": {
        target: proxyTarget,
        changeOrigin: true,
      },
      "/ws": {
        target: proxyTarget,
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
