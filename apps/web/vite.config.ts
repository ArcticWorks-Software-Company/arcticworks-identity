import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vite";

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy":
    "camera=(), geolocation=(), microphone=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)",
  "X-XSS-Protection": "0",
};

export default defineConfig({
  plugins: [sveltekit()],
  server: { port: 5173, strictPort: true, headers: securityHeaders },
  preview: { port: 5173, strictPort: true, headers: securityHeaders },
});
