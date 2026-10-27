import colors from "vuetify/es5/util/colors";

export default {
  // Disable server-side rendering: https://go.nuxtjs.dev/ssr-mode
  ssr: false,

  // Global page headers: https://go.nuxtjs.dev/config-head
  head: {
    titleTemplate: "%s - by UTH",
    title: "Privacy Enhanced Network Profiler",
    htmlAttrs: {
      lang: "en",
    },
    meta: [
      { charset: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { hid: "description", name: "description", content: "" },
      { name: "format-detection", content: "telephone=no" },
    ],
    link: [{ rel: "icon", type: "image/x-icon", href: "/favicon_uth.ico" }],
  },

  // Global CSS: https://go.nuxtjs.dev/config-css
  css: [],

  // Plugins to run before rendering page: https://go.nuxtjs.dev/config-plugins
  plugins: ["~/plugins/auth.js", "~/plugins/api.js", "~/plugins/theme.js"],

  router: {
    middleware: ["auth"],
  },

  // Auto import components: https://go.nuxtjs.dev/config-components
  components: true,

  // Modules for dev and build (recommended): https://go.nuxtjs.dev/config-modules
  buildModules: [
    // https://go.nuxtjs.dev/vuetify
    "@nuxtjs/vuetify",
  ],

  env: {
    API_BASE_URL: process.env.API_BASE_URL || "http://127.0.0.1:5555",
    WS_URL: process.env.WS_URL || "ws://127.0.0.1:5002",
  },

  // Vuetify module configuration: https://go.nuxtjs.dev/config-vuetify
  vuetify: {
    customVariables: ["~/assets/variables.scss"],
    theme: {
      dark: true,
      themes: {
        dark: {
          primary: "#38bdf8",
          accent: "#38bdf8",
          secondary: "#94a3b8",
          info: "#38bdf8",
          warning: "#fbbf24",
          error: "#f87171",
          success: "#34d399",
        },
        light: {
          primary: "#0284c7",
          accent: "#0284c7",
          secondary: "#64748b",
          info: "#0284c7",
          warning: "#d97706",
          error: "#dc2626",
          success: "#059669",
        },
      },
    },
  },

  // Build Configuration: https://go.nuxtjs.dev/config-build
  build: {
    transpile: ["mqtt"],
  },
};
