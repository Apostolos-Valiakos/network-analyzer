<template>
  <v-container class="futuristic-light-container" fluid>
    <v-snackbar v-model="snackbar" :color="snackbarType" timeout="3000">
      {{ snackbarText }}
      <template v-slot:actions>
        <v-btn color="white" variant="text" @click="snackbar = false"
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
                variant="outlined"
                density="compact"
                hide-details
              ></v-text-field>
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                v-model="endTime"
                label="End Time"
                type="datetime-local"
                variant="outlined"
                density="compact"
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
                density="compact"
                hide-details
              ></v-switch>
              <v-btn
                color="primary"
                @click="fetchData"
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
          <v-btn
            color="secondary"
            variant="flat"
            class="mb-3"
            prepend-icon="mdi-download"
            @click="downloadHeadersPcap"
            >Headers Only</v-btn
          >
          <v-btn
            color="green-darken-1"
            variant="flat"
            prepend-icon="mdi-download-multiple"
            @click="downloadFullPcap"
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
            variant="outlined"
            density="compact"
            hide-details
            class="mb-3"
          ></v-text-field>
          <div class="d-flex" style="gap: 8px">
            <v-btn
              color="info"
              variant="flat"
              class="flex-grow-1"
              prepend-icon="mdi-file-delimited"
              @click="downloadAnalytics('csv')"
              >CSV</v-btn
            >
            <v-btn
              color="warning"
              variant="flat"
              class="flex-grow-1"
              prepend-icon="mdi-code-json"
              @click="downloadAnalytics('json')"
              >JSON</v-btn
            >
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4" v-if="!loading && stats.length > 0">
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

      <v-col cols="12"
        ><v-card class="elevation-4 rounded-xl pa-4"
          ><h3 class="text-h6 mb-4">Traffic Trend (Bytes over Time)</h3>
          <div id="trend-chart" style="height: 350px"></div></v-card
      ></v-col>
      <v-col cols="12"
        ><v-card class="elevation-4 rounded-xl pa-4"
          ><h3 class="text-h6 mb-4">Network Conversations (Topology)</h3>
          <div id="conversations-chart" style="height: 450px"></div></v-card
      ></v-col>
      <v-col cols="12" md="4"
        ><v-card class="elevation-4 rounded-xl pa-4"
          ><h3 class="text-h6 mb-4">Protocol Distribution</h3>
          <div id="protocol-chart" style="height: 300px"></div></v-card
      ></v-col>
      <v-col cols="12" md="4"
        ><v-card class="elevation-4 rounded-xl pa-4"
          ><h3 class="text-h6 mb-4">Connection States</h3>
          <div id="state-chart" style="height: 300px"></div></v-card
      ></v-col>
      <v-col cols="12" md="4"
        ><v-card class="elevation-4 rounded-xl pa-4"
          ><h3 class="text-h6 mb-4">Top Talkers (Bytes Out)</h3>
          <div id="top-talkers-chart" style="height: 300px"></div></v-card
      ></v-col>
    </v-row>

    <v-row class="mt-4" v-if="!loading && stats.length > 0">
      <v-col cols="12">
        <v-card class="elevation-4 rounded-xl pa-4">
          <div class="d-flex justify-space-between align-center mb-4">
            <h3 class="text-h6">Network Flow Logs</h3>
            <v-text-field
              v-model="search"
              append-icon="mdi-magnify"
              label="Search IP or Protocol"
              single-line
              hide-details
              density="compact"
              style="max-width: 300px"
            ></v-text-field>
          </div>
          <v-data-table
            :headers="flowHeaders"
            :items="stats"
            :search="search"
            class="elevation-0"
            density="compact"
            :items-per-page="5"
          >
            <template v-slot:item.ts="{ item }">{{
              new Date(item.ts * 1000).toLocaleTimeString()
            }}</template>
            <template v-slot:item.orig_bytes="{ item }">{{
              formatBytes(item.orig_bytes)
            }}</template>
            <template v-slot:item.resp_bytes="{ item }">{{
              formatBytes(item.resp_bytes)
            }}</template>
            <template v-slot:item.conn_state="{ item }">
              <v-chip
                size="small"
                :color="
                  item.conn_state === 'S0'
                    ? 'warning'
                    : item.conn_state === 'REJ'
                    ? 'error'
                    : 'success'
                "
                >{{ item.conn_state }}</v-chip
              >
            </template>
          </v-data-table>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4">
      <v-col cols="12">
        <v-card class="elevation-4 rounded-xl pa-6 mb-8 connection-card">
          <h3 class="text-h5 font-weight-bold mb-4 text-primary">
            <v-icon color="primary" class="mr-2" size="large">mdi-brain</v-icon>
            Live Rule Based Analysis
          </h3>

          <v-alert v-if="cnnError" type="error" class="mb-4" variant="tonal">{{
            cnnError
          }}</v-alert>

          <div class="d-flex align-center mb-6">
            <v-btn
              color="primary"
              size="large"
              @click="startLiveAnalysis"
              :loading="cnnLoading"
              :disabled="cnnLoading"
              class="white--text control-btn"
            >
              <v-icon start>mdi-send-circle</v-icon> Run Analysis on Latest
              Slice
            </v-btn>
            <v-progress-linear
              v-if="cnnLoading"
              indeterminate
              color="deep-purple-accent-4"
              class="ml-4 rounded-lg"
              height="10"
            ></v-progress-linear>
          </div>

          <template v-if="cnnResults">
            <v-row class="mb-6">
              <v-col
                v-for="(val, key) in overview"
                :key="key"
                cols="12"
                sm="6"
                md="4"
              >
                <v-card class="pa-4 status-card text-center" elevation="4">
                  <div
                    class="text-caption text-white text-opacity-80 text-uppercase font-weight-bold mb-1"
                  >
                    {{ labels[key] }}
                  </div>
                  <div class="text-h4 font-weight-black text-white">
                    {{ val }}
                  </div>
                </v-card>
              </v-col>
            </v-row>

            <v-card
              class="pa-4 mb-6 rounded-xl elevation-2"
              variant="outlined"
              v-if="formattedCnnChartData.length"
            >
              <PieChart
                :chartData="formattedCnnChartData"
                chartTitle="Role Distribution Summary"
              />
            </v-card>

            <h4 class="text-h6 font-weight-bold mb-3">Identified Roles</h4>
            <v-data-table
              :headers="cnnHeaders"
              :items="enhancedTableItems"
              class="packet-table elevation-2 rounded-lg"
              density="comfortable"
              hover
            >
              <template v-slot:item.class_name="{ item }">
                <div class="d-flex align-center font-weight-bold">
                  <v-avatar
                    size="24"
                    color="primary"
                    variant="tonal"
                    class="mr-2"
                    ><span class="text-caption">{{
                      item.class_name.charAt(0)
                    }}</span></v-avatar
                  >
                  {{ item.class_name }}
                </div>
              </template>
              <template v-slot:item.percentage="{ item }">
                <div class="d-flex align-center" style="width: 100%">
                  <v-progress-linear
                    :model-value="item.percentage"
                    color="primary"
                    height="8"
                    rounded
                    striped
                    class="mr-2"
                  ></v-progress-linear>
                  <span
                    class="text-caption text-medium-emphasis font-weight-bold"
                    >{{ item.percentage }}%</span
                  >
                </div>
              </template>
              <template v-slot:item.ips="{ item }">
                <div v-if="item.ips?.length" class="py-2">
                  <v-chip
                    v-for="ip in item.ips"
                    :key="ip"
                    size="small"
                    color="primary"
                    variant="flat"
                    class="mr-1 mb-1 font-weight-bold shadow-sm"
                    >{{ ip }}</v-chip
                  >
                </div>
                <div v-else class="text-grey text-caption font-italic">
                  No IPs assigned
                </div>
              </template>
            </v-data-table>
          </template>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-2">
      <v-col cols="12">
        <v-card class="elevation-4 rounded-xl pa-6 mb-8 connection-card">
          <h3 class="text-h5 font-weight-bold mb-4 text-indigo-darken-1">
            <v-icon color="indigo-darken-1" class="mr-2" size="large"
              >mdi-radar-scan</v-icon
            >
            Advanced Service Inspection (Nmap)
          </h3>

          <v-alert v-if="scanError" type="error" class="mb-4" variant="tonal">
            {{ scanError }}
          </v-alert>

          <v-row class="mb-4">
            <v-col cols="12" md="4">
              <v-select
                v-model="scanProfile"
                :items="scanProfiles"
                label="Select Scan Profile"
                variant="outlined"
                density="comfortable"
                hide-details
              ></v-select>
            </v-col>
            <v-col cols="12" md="8" class="d-flex align-center">
              <v-text-field
                v-model="customScanTarget"
                label="Custom Target (e.g. 192.168.100.1/26) [Leave blank to auto-scan all IPs]"
                variant="outlined"
                density="comfortable"
                hide-details
                class="flex-grow-1 mr-4"
              ></v-text-field>
            </v-col>
          </v-row>

          <div class="d-flex align-center mb-6">
            <v-btn
              color="indigo-darken-1"
              size="large"
              @click="startBackgroundScan"
              :loading="scanStatus === 'running'"
              :disabled="
                scanStatus === 'running' ||
                (!customScanTarget && !analyzedIps.length)
              "
              class="white--text control-btn"
            >
              <v-icon start>mdi-shield-search</v-icon>
              {{
                scanStatus === "running"
                  ? "Scan in Progress..."
                  : "Launch Background Scan"
              }}
            </v-btn>

            <span
              v-if="scanStatus === 'running'"
              class="ml-3 text-subtitle-2 text-indigo font-weight-bold blink-text"
              >Scanning targets (This may take several minutes)...</span
            >
          </div>

          <template v-if="scanResults && Object.keys(scanResults).length > 0">
            <h4 class="text-h6 font-weight-bold mb-3 mt-4 text-success">
              <v-icon color="success" class="mr-2">mdi-check-circle</v-icon>Scan
              Completed
            </h4>
            <v-expansion-panels variant="accordion">
              <v-expansion-panel
                v-for="(data, ip) in scanResults"
                :key="ip"
                class="mb-2"
              >
                <v-expansion-panel-title class="font-weight-bold text-indigo">
                  <v-icon start color="indigo">mdi-server-network</v-icon> Host:
                  {{ ip }}
                  <v-chip size="small" color="info" class="ml-4"
                    >{{ data.services.length }} Services Found</v-chip
                  >
                </v-expansion-panel-title>
                <v-expansion-panel-text>
                  <v-data-table
                    :headers="serviceHeaders"
                    :items="data.services"
                    density="compact"
                    class="elevation-1 mt-2"
                    hide-default-footer
                  >
                    <template v-slot:item.port="{ item }">
                      <v-chip
                        size="small"
                        color="primary"
                        variant="flat"
                        class="font-weight-bold"
                        >{{ item.port }} /
                        {{ item.protocol.toUpperCase() }}</v-chip
                      >
                    </template>

                    <template v-slot:item.cpes="{ item }">
                      <div v-if="item.cpes.length">
                        <v-chip
                          v-for="cpe in item.cpes"
                          :key="cpe"
                          size="x-small"
                          color="grey-darken-2"
                          variant="outlined"
                          class="mr-1 mt-1"
                          >{{ cpe }}</v-chip
                        >
                      </div>
                      <span v-else class="text-caption text-grey font-italic"
                        >No CPEs detected</span
                      >
                    </template>

                    <template v-slot:item.scripts="{ item }">
                      <div v-if="item.scripts && item.scripts.length">
                        <v-alert
                          v-for="script in item.scripts"
                          :key="script.id"
                          density="compact"
                          type="error"
                          variant="tonal"
                          class="mt-2 text-caption"
                        >
                          <strong>{{ script.id }}</strong
                          >:
                          <pre style="white-space: pre-wrap; font-size: 10px">{{
                            script.output
                          }}</pre>
                        </v-alert>
                      </div>
                      <span v-else class="text-caption text-grey font-italic"
                        >No vulnerabilities detected</span
                      >
                    </template>
                  </v-data-table>
                </v-expansion-panel-text>
              </v-expansion-panel>
            </v-expansion-panels>
          </template>

          <v-alert
            v-else-if="scanStatus === 'completed'"
            type="info"
            variant="tonal"
            class="mt-4"
          >
            Scan completed, but no open services were detected on the targeted
            IPs.
          </v-alert>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import * as echarts from "echarts";
import { io } from "socket.io-client";
import PieChart from "@/components/PieChart.vue";

export default {
  name: "ContinuousMonitoring",
  components: { PieChart },
  data() {
    return {
      socket: null,
      apiUrl: process.env.VUE_APP_API_BASE_URL || "http://10.16.2.143:5555",
      startTime: this.getLocalISOString(new Date(Date.now() - 3600000)),
      endTime: this.getLocalISOString(new Date()),
      isLive: true,
      loading: false,
      search: "",
      stats: [],
      snackbar: false,
      snackbarText: "",
      snackbarType: "info",

      // CNN Variables
      cnnLoading: false,
      cnnResults: null,
      cnnError: null,

      // Async Nmap Variables
      // Async Nmap Variables
      scanProfile: "deep",
      scanProfiles: [
        { text: "Fast Scan (-F)", value: "fast" },
        { text: "Deep Version Scan (-sV)", value: "deep" },
        { text: "Vulnerability Scan (10k ports + Vulners)", value: "vuln" },
      ],
      customScanTarget: "",
      scanStatus: "idle",
      scanResults: null,
      scanError: null,
      scanInterval: null,

      // Chart Instances
      protoChart: null,
      topTalkersChart: null,
      trendChart: null,
      stateChart: null,
      conversationsChart: null,
      topologyInterval: null,

      // CHANGED BACK TO text AND value FOR VUETIFY 2
      flowHeaders: [
        { text: "Time", value: "ts" },
        { text: "Source IP", value: "id.orig_h" },
        { text: "Dest IP", value: "id.resp_h" },
        { text: "Protocol", value: "proto" },
        { text: "State", value: "conn_state" },
        { text: "Bytes Out", value: "orig_bytes" },
        { text: "Bytes In", value: "resp_bytes" },
      ],
      cnnHeaders: [
        {
          text: "Role / Class Name",
          value: "class_name",
          align: "start",
          width: "25%",
        },
        { text: "Count", value: "count", sortable: true, width: "15%" },
        {
          text: "Distribution",
          value: "percentage",
          align: "center",
          width: "20%",
        },
        { text: "Assigned IP Addresses", value: "ips", sortable: false },
      ],
      serviceHeaders: [
        { text: "Port", value: "port", width: "12%" },
        { text: "Service", value: "name", width: "15%" },
        { text: "CPE Info", value: "cpes", width: "25%" },
        { text: "NSE Script Output", value: "scripts", width: "48%" },
      ],
      exportLimit: null,
    };
  },
  computed: {
    startTimestamp() {
      return new Date(this.startTime).getTime() / 1000;
    },
    endTimestamp() {
      return new Date(this.endTime).getTime() / 1000;
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

    analyzedIps() {
      if (!this.cnnResults?.rule_based_classification_summary) return [];
      const ipSet = new Set();
      this.cnnResults.rule_based_classification_summary.forEach((item) => {
        if (item.ips) item.ips.forEach((ip) => ipSet.add(ip));
      });
      return Array.from(ipSet);
    },

    overview() {
      if (!this.cnnResults) return {};
      return {
        most_frequent_class: this.cnnResults.most_frequent_class || "N/A",
        total_classified: this.cnnResults.total_classified || 0,
        processing_time: this.cnnResults.processing_time
          ? `${this.cnnResults.processing_time.toFixed(2)}s`
          : "0s",
      };
    },
    labels() {
      return {
        most_frequent_class: "Most Frequent Class",
        total_classified: "Total Classified IPs",
        processing_time: "Processing Time",
      };
    },
    enhancedTableItems() {
      if (!this.cnnResults?.rule_based_classification_summary) return [];
      const total = this.cnnResults.rule_based_classification_summary.reduce(
        (sum, item) => sum + item.count,
        0
      );
      return this.cnnResults.rule_based_classification_summary.map((item) => ({
        ...item,
        percentage: total > 0 ? ((item.count / total) * 100).toFixed(1) : 0,
      }));
    },
    formattedCnnChartData() {
      if (!this.cnnResults?.rule_based_classification_summary) return [];
      return this.cnnResults.rule_based_classification_summary.map((item) => ({
        name: item.class_name,
        value: item.count,
      }));
    },
  },
  mounted() {
    this.fetchData();
    window.addEventListener("resize", this.resizeCharts);
    this.socket = io(this.apiUrl, {
      transports: ["websocket", "polling"],
      upgrade: true,
    });
    this.socket.on("new_network_data", (newFlows) => {
      if (this.isLive) {
        this.stats = [...newFlows, ...this.stats].slice(0, 1000);
        this.updateCharts();
      }
    });
    this.topologyInterval = setInterval(() => {
      if (this.isLive && this.stats.length > 0) this.renderConversationsChart();
    }, 60000);
  },
  unmounted() {
    if (this.socket) this.socket.disconnect();
    if (this.topologyInterval) clearInterval(this.topologyInterval);
    if (this.scanInterval) clearInterval(this.scanInterval);
    window.removeEventListener("resize", this.resizeCharts);
  },
  methods: {
    // ----------------------------------------
    // Async Background Nmap Methods
    // ----------------------------------------
    async startBackgroundScan() {
      this.scanStatus = "running";
      this.scanError = null;
      this.scanResults = null;

      // Decide payload: Custom target string OR list of extracted IPs
      const payload = this.customScanTarget.trim()
        ? { target: this.customScanTarget.trim(), profile: this.scanProfile }
        : { targets: this.analyzedIps, profile: this.scanProfile };

      try {
        const response = await fetch(`${this.apiUrl}/v1/scan/start`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok)
          throw new Error(data.error || "Failed to start background scan.");

        this.pollScanResults();
      } catch (error) {
        this.scanError = error.message;
        this.scanStatus = "failed";
      }
    },

    pollScanResults() {
      if (this.scanInterval) clearInterval(this.scanInterval);

      this.scanInterval = setInterval(async () => {
        try {
          const res = await fetch(`${this.apiUrl}/v1/scan/results`);
          const data = await res.json();

          if (data.status === "completed") {
            clearInterval(this.scanInterval);
            this.scanResults = data.data;
            this.scanStatus = "completed";
          } else if (data.status === "failed") {
            clearInterval(this.scanInterval);
            this.scanError =
              data.error || "The background scan encountered an error.";
            this.scanStatus = "failed";
          }
        } catch (error) {
          console.error("Polling error:", error);
        }
      }, 5000);
    },

    // ----------------------------------------
    // Live Analysis Methods
    // ----------------------------------------
    async startLiveAnalysis() {
      this.cnnLoading = true;
      this.cnnError = null;
      try {
        const response = await fetch(`${this.apiUrl}/v1/analyze_live`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        const data = await response.json();
        if (!response.ok)
          throw new Error(data.message || "Failed to analyze live PCAP.");
        this.cnnResults = data;
      } catch (error) {
        this.cnnError = error.message;
      } finally {
        this.cnnLoading = false;
      }
    },

    // Standard Charts & Stats Logic below...
    updateCharts() {
      this.$nextTick(() => {
        if (this.stats.length > 0) {
          this.renderProtocolChart();
          this.renderTopTalkersChart();
          this.renderTrendChart();
          this.renderStateChart();
        }
      });
    },
    renderConversationsChart() {
      /* Removed large echarts init for brevity */
    },
    downloadAnalytics(format) {
      let url = `${this.apiUrl}/v1/network/export?start_time=${this.startTimestamp}&end_time=${this.endTimestamp}&format=${format}`;
      if (this.exportLimit) url += `&limit=${this.exportLimit}`;
      window.open(url, "_blank");
    },
    getLocalISOString(date) {
      const offset = date.getTimezoneOffset() * 60000;
      return new Date(date - offset).toISOString().slice(0, 16);
    },
    showSnackbar(text, type = "info") {
      this.snackbarText = text;
      this.snackbarType = type;
      this.snackbar = true;
    },
    formatBytes(bytes) {
      if (!bytes || bytes === 0) return "0 B";
      const k = 1024,
        sizes = ["B", "KB", "MB", "GB", "TB"],
        i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    },
    async fetchData() {
      await this.fetchStatistics();
    },
    async fetchStatistics(showLoader = true) {
      if (showLoader) this.loading = true;
      try {
        const res = await fetch(
          `${this.apiUrl}/v1/network/statistics?start_time=${this.startTimestamp}&end_time=${this.endTimestamp}&format=json&limit=5000`
        );
        if (!res.ok) throw new Error("Failed to fetch");
        this.stats = (await res.json()).reverse();
        this.updateCharts();
      } catch (err) {
        if (showLoader) this.showSnackbar("Could not load stats.", "error");
      } finally {
        if (showLoader) this.loading = false;
      }
    },
    renderTrendChart() {
      /* Truncated setup */
    },
    renderStateChart() {
      /* Truncated setup */
    },
    renderProtocolChart() {
      /* Truncated setup */
    },
    renderTopTalkersChart() {
      /* Truncated setup */
    },
    resizeCharts() {
      [
        this.protoChart,
        this.topTalkersChart,
        this.trendChart,
        this.stateChart,
        this.conversationsChart,
      ].forEach((c) => {
        if (c) c.resize();
      });
    },
    downloadHeadersPcap() {
      window.open(
        `${this.apiUrl}/v1/network/pcap/headers?start_time=${this.startTimestamp}&end_time=${this.endTimestamp}`,
        "_blank"
      );
    },
    downloadFullPcap() {
      window.open(`${this.apiUrl}/v1/network/pcap/latest/full`, "_blank");
    },
  },
};
</script>

<style scoped>
.futuristic-light-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 50%, #cbd5e1 100%);
}
.status-card {
  background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%) !important;
}
.connection-card {
  border: 2px solid rgba(59, 130, 246, 0.5);
}
.control-btn {
  border-radius: 12px !important;
  font-weight: bold;
  letter-spacing: 0.5px;
}
.waiting-state {
  background: rgba(248, 250, 252, 0.8);
  color: #64748b;
  border: 2px dashed #cbd5e1;
}
.waiting-title {
  color: #1e40af;
  font-weight: 700;
}
.packet-table :deep(.v-data-table__wrapper) {
  border-radius: 8px;
}
.blink-text {
  animation: blinker 1.5s linear infinite;
}
@keyframes blinker {
  50% {
    opacity: 0.3;
  }
}
</style>
