<template>
  <v-container class="dark-page-container" fluid>
    <v-snackbar v-model="snackbar" :color="snackbarType" timeout="3000">
      {{ snackbarText }}
      <template v-slot:action="{ attrs }">
        <v-btn color="white" text v-bind="attrs" @click="snackbar = false"
          >Close</v-btn
        >
      </template>
    </v-snackbar>

    <v-row>
      <v-col cols="12">
        <v-card class="elevation-8 rounded-xl pa-6 status-card">
          <div class="d-flex justify-space-between align-center">
            <div>
              <h2 class="text-h4 font-weight-bold text-white mb-2">
                Continuous Monitoring Dashboard
              </h2>
              <p class="text-white text-opacity-80 mb-0">
                Live network statistics, traffic trends, and role snapshots
              </p>
            </div>
            <v-icon size="64" color="white" class="opacity-50"
              >mdi-monitor-dashboard</v-icon
            >
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4">
      <v-col cols="12" md="5">
        <v-card class="elevation-4 rounded-xl pa-4 h-100">
          <h3 class="text-h6 mb-4">Timeframe Selection</h3>
          <v-row>
            <v-col cols="12" sm="6">
              <v-text-field
                v-model="startTime"
                label="Start Time"
                type="datetime-local"
                hide-details
              ></v-text-field>
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                v-model="endTime"
                label="End Time"
                type="datetime-local"
                hide-details
              ></v-text-field>
            </v-col>
            <v-col
              cols="12"
              class="d-flex align-center justify-space-between mt-2"
            >
              <v-switch
                v-model="isLive"
                label="Live Mode"
                color="success"
                hide-details
              ></v-switch>
              <v-btn
                color="primary"
                @click="fetchStatistics"
                :loading="loading"
                width="120"
                >Apply</v-btn
              >
            </v-col>
          </v-row>
        </v-card>
      </v-col>

      <v-col cols="12" md="3">
        <v-card
          class="elevation-4 rounded-xl pa-4 h-100 d-flex flex-column justify-center"
        >
          <h3 class="text-subtitle-1 font-weight-bold mb-3 text-center">
            Raw PCAP
          </h3>
          <v-btn color="secondary" class="mb-3" @click="downloadHeadersPcap"
            >Headers Only</v-btn
          >
          <v-btn color="green-darken-1" @click="downloadFullPcap"
            >Full Payload</v-btn
          >
        </v-card>
      </v-col>

      <v-col cols="12" md="4">
        <v-card
          class="elevation-4 rounded-xl pa-4 h-100 d-flex flex-column justify-center"
        >
          <h3 class="text-subtitle-1 font-weight-bold mb-2 text-center">
            Export Analytics
          </h3>
          <v-text-field
            v-model="exportLimit"
            label="Limit (Optional, leave blank for all)"
            type="number"
            hide-details
            class="mb-3"
          ></v-text-field>
          <div class="d-flex" style="gap: 8px">
            <v-btn color="info" class="flex-grow-1" @click="downloadAnalytics('csv')"
              >CSV</v-btn
            >
            <v-btn
              color="warning"
              class="flex-grow-1"
              @click="downloadAnalytics('json')"
              >JSON</v-btn
            >
          </div>
        </v-card>
      </v-col>
    </v-row>

    <template v-if="!loading && stats.length > 0">
      <v-row class="mt-4">
        <v-col cols="12" md="4">
          <v-card class="elevation-4 rounded-xl pa-4 text-center">
            <h4 class="text-subtitle-1 text-grey-darken-1">
              Total Bytes Transferred
            </h4>
            <h2 class="text-h3 text-primary font-weight-bold">
              {{ formatBytes(totalBytes) }}
            </h2>
          </v-card>
        </v-col>
        <v-col cols="12" md="4">
          <v-card class="elevation-4 rounded-xl pa-4 text-center">
            <h4 class="text-subtitle-1 text-grey-darken-1">Total Packets</h4>
            <h2 class="text-h3 text-info font-weight-bold">
              {{ totalPackets.toLocaleString() }}
            </h2>
          </v-card>
        </v-col>
        <v-col cols="12" md="4">
          <v-card class="elevation-4 rounded-xl pa-4 text-center">
            <h4 class="text-subtitle-1 text-grey-darken-1">Total Flow Records</h4>
            <h2 class="text-h3 text-success font-weight-bold">
              {{ stats.length }}
            </h2>
          </v-card>
        </v-col>
      </v-row>

      <MonitoringCharts :stats="stats" :live="isLive" />

      <v-row class="mt-4">
        <v-col cols="12">
          <FlowLogTable :stats="stats" />
        </v-col>
      </v-row>
    </template>

    <v-row class="mt-4">
      <v-col cols="12">
        <LiveAnalysisPanel @analyzed="analyzedIps = $event" />
      </v-col>
    </v-row>

    <v-row class="mt-2">
      <v-col cols="12">
        <ScanPanel :analyzed-ips="analyzedIps" />
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import { io } from "socket.io-client";
import FlowLogTable from "@/components/monitoring/FlowLogTable.vue";
import LiveAnalysisPanel from "@/components/monitoring/LiveAnalysisPanel.vue";
import MonitoringCharts from "@/components/monitoring/MonitoringCharts.vue";
import ScanPanel from "@/components/monitoring/ScanPanel.vue";
import { saveBlob } from "@/utils/download";
import { formatBytes } from "@/utils/format";

function localDateTimeInput(date) {
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date - offset).toISOString().slice(0, 16);
}

export default {
  name: "ContinuousMonitoring",
  components: { FlowLogTable, LiveAnalysisPanel, MonitoringCharts, ScanPanel },
  data() {
    return {
      startTime: localDateTimeInput(new Date(Date.now() - 3600000)),
      endTime: localDateTimeInput(new Date()),
      isLive: true,
      loading: false,
      stats: [],
      analyzedIps: [],
      exportLimit: null,
      snackbar: false,
      snackbarText: "",
      snackbarType: "info",
    };
  },
  computed: {
    startTimestamp() {
      return new Date(this.startTime).getTime() / 1000;
    },
    endTimestamp() {
      return new Date(this.endTime).getTime() / 1000;
    },
    timeRangeQuery() {
      return `start_time=${this.startTimestamp}&end_time=${this.endTimestamp}`;
    },
    totalBytes() {
      return this.stats.reduce(
        (acc, curr) =>
          acc +
          (parseInt(curr.orig_bytes) || 0) +
          (parseInt(curr.resp_bytes) || 0),
        0
      );
    },
    totalPackets() {
      return this.stats.reduce(
        (acc, curr) =>
          acc +
          (parseInt(curr.orig_pkts) || 0) +
          (parseInt(curr.resp_pkts) || 0),
        0
      );
    },
  },
  mounted() {
    this.fetchStatistics();
    this.socket = io(this.$api.baseUrl, {
      transports: ["websocket", "polling"],
      upgrade: true,
    });
    this.socket.on("connect", () => {
      this.showSnackbar("Live feed connected.", "success");
    });
    this.socket.on("disconnect", () => {
      this.showSnackbar("Live feed disconnected.", "warning");
    });
    this.socket.on("connect_error", () => {
      this.showSnackbar("Could not connect to live feed.", "error");
    });
    this.socket.on("new_network_data", (newFlows) => {
      if (this.isLive) {
        this.stats = [...newFlows, ...this.stats].slice(0, 1000);
      }
    });
  },
  beforeDestroy() {
    this.socket.disconnect();
  },
  methods: {
    formatBytes,
    showSnackbar(text, type = "info") {
      this.snackbarText = text;
      this.snackbarType = type;
      this.snackbar = true;
    },
    async fetchStatistics() {
      this.loading = true;
      try {
        const res = await this.$apiFetch(
          this.$api.url(
            `/v1/network/statistics?${this.timeRangeQuery}&format=json&limit=5000`
          )
        );
        if (!res.ok) throw new Error("Failed to fetch");
        this.stats = (await res.json()).reverse();
      } catch (err) {
        this.showSnackbar("Could not load stats.", "error");
      } finally {
        this.loading = false;
      }
    },
    async download(path, filename, errorMessage) {
      try {
        const res = await this.$apiFetch(this.$api.url(path));
        if (!res.ok) throw new Error(errorMessage);
        saveBlob(await res.blob(), filename);
      } catch (err) {
        this.showSnackbar(err.message, "error");
      }
    },
    downloadAnalytics(format) {
      let path = `/v1/network/export?${this.timeRangeQuery}&format=${format}`;
      if (this.exportLimit) path += `&limit=${this.exportLimit}`;
      return this.download(path, `network_analytics.${format}`, "Export failed");
    },
    downloadHeadersPcap() {
      return this.download(
        `/v1/network/pcap/headers?${this.timeRangeQuery}`,
        `headers_${this.startTimestamp}.pcap`,
        "Download failed"
      );
    },
    downloadFullPcap() {
      return this.download(
        "/v1/network/pcap/latest/full",
        "latest_full.pcap",
        "Download failed"
      );
    },
  },
};
</script>

<style scoped>
.dark-page-container {
  min-height: 100vh;
  padding: 16px;
}
.status-card {
  background: var(--status-card-bg) !important;
}
</style>
