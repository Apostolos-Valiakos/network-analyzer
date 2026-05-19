<template>
  <v-app>
    <AppHeader />
    <v-main>
      <v-container style="max-width: 100% !important; padding: 0% !important">
        <Nuxt />
      </v-container>
    </v-main>
    <AppFooter />
  </v-app>
</template>

<script>
import AppFooter from "../components/AppFooter.vue";
import AppHeader from "../components/AppHeader.vue";

export default {
  components: {
    AppHeader,
    AppFooter,
  },
  name: "DefaultLayout",
  data() {
    return {
      title: "Privacy Enhanced Network Profiler",
    };
  },
};
</script>

<style>
/* ── CSS design tokens (change with theme) ───────────────────────── */
.theme--dark {
  --app-bg: #0f172a;
  --surface: #1e293b;
  --surface-alt: #162032;
  --border: rgba(255, 255, 255, 0.08);
  --accent-border: rgba(56, 189, 248, 0.2);
  --text-secondary: rgba(255, 255, 255, 0.65);
  --text-muted: rgba(255, 255, 255, 0.45);
  --highlight-bg: rgba(56, 189, 248, 0.05);
  --highlight-border: rgba(56, 189, 248, 0.3);
  --stepper-hdr-bg: rgba(56, 189, 248, 0.07);
  --metric-value: #38bdf8;
  --metric-box-bg: rgba(56, 189, 248, 0.06);
  --metric-box-border: rgba(56, 189, 248, 0.15);
  --packet-item-border: rgba(255, 255, 255, 0.07);
  --status-card-bg: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%);
  --waiting-bg: rgba(56, 189, 248, 0.04);
  --waiting-border: rgba(56, 189, 248, 0.2);
  --waiting-title: #38bdf8;
  --blink-color: #38bdf8;
  --connection-border: rgba(56, 189, 248, 0.25);
}

.theme--light {
  --app-bg: #f1f5f9;
  --surface: #ffffff;
  --surface-alt: #f8fafc;
  --border: rgba(0, 0, 0, 0.1);
  --accent-border: rgba(2, 132, 199, 0.25);
  --text-secondary: rgba(0, 0, 0, 0.6);
  --text-muted: rgba(0, 0, 0, 0.4);
  --highlight-bg: rgba(2, 132, 199, 0.05);
  --highlight-border: rgba(2, 132, 199, 0.3);
  --stepper-hdr-bg: rgba(2, 132, 199, 0.07);
  --metric-value: #0284c7;
  --metric-box-bg: rgba(2, 132, 199, 0.06);
  --metric-box-border: rgba(2, 132, 199, 0.15);
  --packet-item-border: rgba(0, 0, 0, 0.08);
  --status-card-bg: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
  --waiting-bg: rgba(2, 132, 199, 0.04);
  --waiting-border: rgba(2, 132, 199, 0.2);
  --waiting-title: #0284c7;
  --blink-color: #0284c7;
  --connection-border: rgba(2, 132, 199, 0.25);
}

/* ── App & Vuetify component backgrounds ─────────────────────────── */
.v-application {
  background-color: var(--app-bg) !important;
}
.theme--dark.v-card,
.theme--dark.v-data-table,
.theme--dark.v-stepper,
.theme--dark.v-expansion-panel,
.theme--dark.v-sheet,
.theme--dark.v-simple-table {
  background-color: var(--surface) !important;
}

/* ── Global utility classes ──────────────────────────────────────── */
.text-fade {
  color: var(--text-secondary) !important;
}
.text-dim {
  color: var(--text-muted) !important;
}
</style>
