import adapter from "@sveltejs/adapter-node";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

const development = process.env.NODE_ENV !== "production";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter(),
    csp: {
      mode: "auto",
      directives: {
        "default-src": ["self"],
        "base-uri": ["none"],
        "connect-src": [
          "self",
          ...(development ? ["http://localhost:8080", "ws://localhost:5173"] : []),
        ],
        "font-src": ["self"],
        "frame-ancestors": ["none"],
        "frame-src": ["none"],
        "img-src": ["self"],
        "object-src": ["none"],
        "script-src": ["self"],
        "style-src": ["self"],
        "style-src-attr": ["none"],
        "worker-src": ["self"],
      },
    },
  },
};

export default config;
