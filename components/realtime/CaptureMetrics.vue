<template>
  <v-card class="data-card pa-4" elevation="0">
    <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
      Real-Time Metrics
    </v-card-title>
    <v-row dense>
      <v-col cols="6">
        <div class="metric-box">
          <div class="metric-label">Packets Captured</div>
          <div class="metric-value">{{ packetCount }}</div>
        </div>
      </v-col>
      <v-col cols="6">
        <div class="metric-box">
          <div class="metric-label">Total Size (MB)</div>
          <div class="metric-value">{{ sizeMb }}</div>
        </div>
      </v-col>
    </v-row>
  </v-card>
</template>

<script>
export default {
  name: "CaptureMetrics",
  props: {
    packetCount: { type: Number, default: 0 },
    totalBytes: { type: Number, default: 0 },
  },
  computed: {
    sizeMb() {
      return (this.totalBytes / (1024 * 1024)).toFixed(2);
    },
  },
};
</script>

<style scoped>
.data-card {
  border: 1px solid var(--border) !important;
  background-color: var(--surface) !important;
  border-radius: 16px !important;
}
.metric-box {
  background-color: var(--metric-box-bg);
  border: 1px solid var(--metric-box-border);
  padding: 12px;
  border-radius: 12px;
  margin-bottom: 8px;
}
.metric-label {
  font-size: 0.8rem;
  color: var(--text-muted);
  font-weight: 500;
  margin-bottom: 4px;
}
.metric-value {
  font-size: 1.5rem;
  font-weight: 800;
  color: var(--metric-value);
}
</style>
