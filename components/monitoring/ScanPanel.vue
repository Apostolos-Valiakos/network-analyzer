<template>
  <v-card class="elevation-4 rounded-xl pa-6 mb-8 connection-card">
    <h3 class="text-h5 font-weight-bold mb-4 text-indigo-darken-1">
      <v-icon color="indigo-darken-1" class="mr-2" size="large"
        >mdi-radar-scan</v-icon
      >
      Advanced Service Inspection (Nmap)
    </h3>

    <v-alert v-if="error" type="error" class="mb-4">{{ error }}</v-alert>

    <v-row class="mb-4">
      <v-col cols="12" md="4">
        <v-select
          v-model="profile"
          :items="profiles"
          label="Select Scan Profile"
          hide-details
        ></v-select>
      </v-col>
      <v-col cols="12" md="8" class="d-flex align-center">
        <v-text-field
          v-model="customTarget"
          label="Custom Target (e.g. 192.168.100.1/26) [Leave blank to auto-scan all IPs]"
          hide-details
          class="flex-grow-1 mr-4"
        ></v-text-field>
      </v-col>
    </v-row>

    <div class="d-flex align-center mb-6">
      <v-btn
        color="indigo-darken-1"
        @click="start"
        :loading="status === 'running'"
        :disabled="status === 'running' || (!customTarget && !analyzedIps.length)"
        class="white--text control-btn"
      >
        <v-icon>mdi-shield-search</v-icon>
        {{ status === "running" ? "Scan in Progress..." : "Launch Background Scan" }}
      </v-btn>

      <span
        v-if="status === 'running'"
        class="ml-3 text-subtitle-2 text-indigo font-weight-bold blink-text"
        >Scanning targets (This may take several minutes)...</span
      >
    </div>

    <template v-if="results && results.length > 0">
      <div class="d-flex align-center mb-3 mt-4">
        <h4 class="text-h6 font-weight-bold text-success mb-0">
          <v-icon color="success" class="mr-2">mdi-check-circle</v-icon>Scan
          Completed
        </h4>
        <v-spacer></v-spacer>
        <v-btn color="primary" @click="downloadCsv">Download CSV</v-btn>
      </div>
      <v-expansion-panels v-model="openPanels" accordion multiple>
        <v-expansion-panel
          v-for="hostResult in results"
          :key="hostResult.host"
          class="mb-2"
        >
          <v-expansion-panel-header class="font-weight-bold text-indigo">
            <div>
              <v-icon color="indigo">mdi-server-network</v-icon> Host:
              {{ hostResult.host }}
              <span v-if="hostResult.hostname" class="text-caption text-grey ml-2"
                >({{ hostResult.hostname }})</span
              >
              <v-chip color="info" class="ml-4"
                >{{ hostResult.ports.length }} Open Ports</v-chip
              >
            </div>
          </v-expansion-panel-header>
          <v-expansion-panel-content>
            <v-data-table
              :headers="headers"
              :items="hostResult.ports"
              class="elevation-1 mt-2"
              hide-default-footer
            >
              <template v-slot:item.port="{ item }">
                <v-chip color="primary" class="font-weight-bold"
                  >{{ item.port }} / {{ item.protocol.toUpperCase() }}</v-chip
                >
              </template>

              <template v-slot:item.version="{ item }">
                <span
                  >{{ item.service
                  }}<span v-if="item.version"> — {{ item.version }}</span></span
                >
              </template>

              <template v-slot:item.cves="{ item }">
                <div v-if="item.cves && item.cves.length">
                  <v-chip
                    v-for="cve in item.cves"
                    :key="cve"
                    color="error"
                    class="mr-1 mt-1"
                    >{{ cve }}</v-chip
                  >
                </div>
                <span v-else class="text-caption text-grey font-italic"
                  >No known CVEs</span
                >
              </template>
            </v-data-table>
          </v-expansion-panel-content>
        </v-expansion-panel>
      </v-expansion-panels>
    </template>

    <v-alert v-else-if="status === 'completed'" type="info" class="mt-4">
      Scan completed, but no open services were detected on the targeted IPs.
    </v-alert>
  </v-card>
</template>

<script>
import { saveBlob } from "@/utils/download";
import { scanResultsToCsv } from "@/utils/scanResults";

const POLL_MS = 30000;

export default {
  name: "ScanPanel",
  props: {
    analyzedIps: { type: Array, required: true },
  },
  data() {
    return {
      profile: "deep",
      profiles: [
        { text: "Fast Scan (-F)", value: "fast" },
        { text: "Deep Version Scan (-sV)", value: "deep" },
        { text: "Vulnerability Scan (10k ports + Vulners)", value: "vuln" },
      ],
      customTarget: "",
      status: "idle",
      results: null,
      error: null,
      openPanels: [],
      headers: [
        { text: "Port", value: "port", width: "15%" },
        { text: "Service / Version", value: "version", width: "40%" },
        { text: "Known CVEs", value: "cves", width: "45%" },
      ],
    };
  },
  beforeDestroy() {
    clearInterval(this.pollTimer);
  },
  methods: {
    async start() {
      this.status = "running";
      this.error = null;
      this.results = null;

      // Custom target string, or the IPs found by the live analysis
      const target = this.customTarget.trim();
      const payload = target
        ? { target, profile: this.profile }
        : { targets: this.analyzedIps, profile: this.profile };

      try {
        const response = await this.$apiFetch(this.$api.url("/v1/scan/start"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok)
          throw new Error(data.message || "Failed to start background scan.");
        this.poll();
      } catch (error) {
        this.error = error.message;
        this.status = "failed";
      }
    },
    poll() {
      clearInterval(this.pollTimer);
      this.pollTimer = setInterval(async () => {
        try {
          const res = await this.$apiFetch(this.$api.url("/v1/scan/results"));
          const data = await res.json();
          if (data.status === "completed") {
            clearInterval(this.pollTimer);
            this.results = data.results;
            // Every host starts expanded, so results are visible straight away
            this.openPanels = data.results.map((_, index) => index);
            this.status = "completed";
          } else if (data.status === "error") {
            clearInterval(this.pollTimer);
            this.error = data.message || "The background scan encountered an error.";
            this.status = "failed";
          }
        } catch (error) {
          console.error("Polling error:", error);
        }
      }, POLL_MS);
    },
    downloadCsv() {
      if (!this.results || !this.results.length) return;
      const blob = new Blob([scanResultsToCsv(this.results)], {
        type: "text/csv;charset=utf-8;",
      });
      saveBlob(blob, `scan_results_${Date.now()}.csv`);
    },
  },
};
</script>

<style scoped>
.connection-card {
  border: 1px solid var(--connection-border) !important;
}
.control-btn {
  border-radius: 12px !important;
  font-weight: bold;
  letter-spacing: 0.5px;
}
.blink-text {
  animation: blinker 1.5s linear infinite;
  color: var(--blink-color);
}
@keyframes blinker {
  50% {
    opacity: 0.3;
  }
}
</style>
