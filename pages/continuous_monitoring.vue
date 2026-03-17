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
          >
            Headers Only
          </v-btn>
          <v-btn
            color="green-darken-1"
            variant="flat"
            prepend-icon="mdi-download-multiple"
            @click="downloadFullPcap"
          >
            Full Payload
          </v-btn>
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

      <v-col cols="12">
        <v-card class="elevation-4 rounded-xl pa-4">
          <h3 class="text-h6 mb-4">Traffic Trend (Bytes over Time)</h3>
          <div id="trend-chart" style="height: 350px"></div>
        </v-card>
      </v-col>
      <v-col cols="12">
        <v-card class="elevation-4 rounded-xl pa-4">
          <h3 class="text-h6 mb-4">Network Conversations (Topology)</h3>
          <div id="conversations-chart" style="height: 450px"></div>
        </v-card>
      </v-col>

      <v-col cols="12" md="4">
        <v-card class="elevation-4 rounded-xl pa-4">
          <h3 class="text-h6 mb-4">Protocol Distribution</h3>
          <div id="protocol-chart" style="height: 300px"></div>
        </v-card>
      </v-col>
      <v-col cols="12" md="4">
        <v-card class="elevation-4 rounded-xl pa-4">
          <h3 class="text-h6 mb-4">Connection States</h3>
          <div id="state-chart" style="height: 300px"></div>
        </v-card>
      </v-col>
      <v-col cols="12" md="4">
        <v-card class="elevation-4 rounded-xl pa-4">
          <h3 class="text-h6 mb-4">Top Talkers (Bytes Out)</h3>
          <div id="top-talkers-chart" style="height: 300px"></div>
        </v-card>
      </v-col>
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
            <template v-slot:item.ts="{ item }">
              {{ new Date(item.ts * 1000).toLocaleTimeString() }}
            </template>
            <template v-slot:item.orig_bytes="{ item }">
              {{ formatBytes(item.orig_bytes) }}
            </template>
            <template v-slot:item.resp_bytes="{ item }">
              {{ formatBytes(item.resp_bytes) }}
            </template>
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
              >
                {{ item.conn_state }}
              </v-chip>
            </template>
          </v-data-table>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4" v-if="!loading && stats.length === 0">
      <v-col cols="12">
        <v-alert type="info" variant="tonal" class="rounded-xl"
          >No network statistics found for the selected timeframe.</v-alert
        >
      </v-col>
    </v-row>

    <v-row class="mt-4">
      <v-col cols="12">
        <v-card class="elevation-4 rounded-xl pa-4">
          <div class="d-flex justify-space-between align-center mb-4">
            <h3 class="text-h6">Latest Network Roles Snapshot</h3>
            <v-chip color="primary" variant="flat"
              >Last Updated: {{ latestSnapshotTime }}</v-chip
            >
          </div>
          <v-data-table
            :headers="roleHeaders"
            :items="roles"
            :loading="loadingRoles"
            class="elevation-0"
            density="comfortable"
          >
            <template v-slot:item.confidence="{ item }">
              <v-progress-linear
                :model-value="item.confidence * 100"
                :color="item.confidence > 0.8 ? 'success' : 'warning'"
                height="8"
                rounded
              ></v-progress-linear>
              <span class="text-caption"
                >{{ (item.confidence * 100).toFixed(0) }}%</span
              >
            </template>
            <template v-slot:item.role="{ item }">
              <v-chip
                :color="getRoleColor(item.role)"
                size="small"
                class="font-weight-bold"
                >{{ item.role }}</v-chip
              >
            </template>
          </v-data-table>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import * as echarts from "echarts";
import { io } from "socket.io-client";

export default {
  name: "ContinuousMonitoring",
  data() {
    return {
      socket: null,
      apiUrl: process.env.VUE_APP_API_BASE_URL || "http://10.16.1.173:5000",
      startTime: this.getLocalISOString(new Date(Date.now() - 3600000)),
      endTime: this.getLocalISOString(new Date()),

      isLive: true,
      liveInterval: null,

      loading: false,
      loadingRoles: false,
      search: "",
      stats: [],
      roles: [],
      snackbar: false,
      snackbarText: "",
      snackbarType: "info",

      // Chart Instances
      protoChart: null,
      topTalkersChart: null,
      trendChart: null,
      stateChart: null,
      conversationsChart: null,
      topologyInterval: null,

      flowHeaders: [
        { text: "Time", value: "ts" },
        { text: "Source IP", value: "id.orig_h" },
        { text: "Dest IP", value: "id.resp_h" },
        { text: "Protocol", value: "proto" },
        { text: "State", value: "conn_state" },
        { text: "Bytes Out", value: "orig_bytes" },
        { text: "Bytes In", value: "resp_bytes" },
      ],
      roleHeaders: [
        { text: "IP Address", value: "id.orig_h", align: "start" },
        { text: "Assigned Role", value: "role" },
        { text: "Confidence", value: "confidence", width: "15%" },
        { text: "Reasoning", value: "reasoning" },
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
    latestSnapshotTime() {
      if (!this.roles.length || !this.roles[0].ts) return "Unknown";
      return new Date(this.roles[0].ts * 1000).toLocaleString();
    },
  },
  mounted() {
    this.fetchData();
    window.addEventListener("resize", this.resizeCharts);

    // Use this.apiUrl directly. If your apiUrl is "http://127.0.0.1:5000",
    // socket.io-client will automatically handle the conversion to ws://
    this.socket = io(this.apiUrl, {
      transports: ["websocket", "polling"], // Allow fallback to polling if WS fails
      upgrade: true,
    });

    this.socket.on("connect", () => {
      console.log("Successfully connected to monitoring WebSocket");
    });

    this.socket.on("connect_error", (error) => {
      console.error("Connection Error:", error);
    });

    this.socket.on("new_network_data", (newFlows) => {
      if (this.isLive) {
        // Process data only if we are on the page and Live Mode is on
        this.stats = [...newFlows, ...this.stats].slice(0, 1000);
        this.updateCharts();
      }
    });
    this.topologyInterval = setInterval(() => {
      if (this.isLive && this.stats.length > 0) {
        this.renderConversationsChart();
      }
    }, 60000);
  },
  unmounted() {
    console.log("Navigating away: Cleaning up background tasks...");

    // 1. STOP WEBSOCKETS
    // This immediately halts the incoming data stream from the Flask server.
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }

    // 2. STOP POLLING
    // This prevents the browser from making any more background HTTP requests.
    if (this.liveInterval) {
      clearInterval(this.liveInterval);
      this.liveInterval = null;
    }

    // 3. CLEAN UP MEMORY
    // Stop the window resize listener and clear chart memory to prevent crashes.
    window.removeEventListener("resize", this.resizeCharts);
    [
      this.protoChart,
      this.topTalkersChart,
      this.trendChart,
      this.stateChart,
      this.conversationsChart,
    ].forEach((c) => {
      if (c) c.dispose();
    });
    if (this.liveInterval) {
      clearInterval(this.liveInterval);
      this.liveInterval = null;
    }

    // NEW: Clear the topology timer
    if (this.topologyInterval) {
      clearInterval(this.topologyInterval);
      this.topologyInterval = null;
    }
  },
  methods: {
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
      const dom = document.getElementById("conversations-chart");
      if (!dom) return;
      if (!this.conversationsChart) this.conversationsChart = echarts.init(dom);

      const linksMap = new Map();

      // 1. Aggregate Connections
      this.stats.forEach((s) => {
        const src = s["id.orig_h"];
        const dst = s["id.resp_h"];
        const proto = s.proto ? s.proto.toUpperCase() : "UNKNOWN";
        const bytes =
          (parseInt(s.orig_bytes) || 0) + (parseInt(s.resp_bytes) || 0);

        if (!src || !dst) return;

        // Track connections as Links (Directional: Src -> Dst)
        const linkId = `${src}-${dst}`;
        if (!linksMap.has(linkId)) {
          linksMap.set(linkId, {
            source: src,
            target: dst,
            bytes: 0,
            protocols: new Set(),
          });
        }

        const linkData = linksMap.get(linkId);
        linkData.bytes += bytes;
        linkData.protocols.add(proto);
      });

      // 2. PERFORMANCE FIX: Limit to Top 50 Connections
      // Prevents the force-directed physics engine from crashing the browser
      const sortedLinks = Array.from(linksMap.values())
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 50);

      // 3. Extract unique Nodes ONLY from those Top 50 links
      const activeNodes = new Set();
      sortedLinks.forEach((l) => {
        activeNodes.add(l.source);
        activeNodes.add(l.target);
      });

      // 4. Format Nodes for ECharts
      const nodes = Array.from(activeNodes).map((ip) => ({
        name: ip,
        symbolSize: 22,
        itemStyle: { color: "#3b82f6", borderColor: "#fff", borderWidth: 2 },
        label: {
          show: true,
          position: "right",
          color: "#475569",
          fontSize: 10,
        },
      }));

      // 5. Format Links for ECharts
      const links = sortedLinks.map((l) => ({
        source: l.source,
        target: l.target,
        bytes: l.bytes,
        protocols: Array.from(l.protocols).join(", "),
        lineStyle: {
          width: Math.min(Math.max(l.bytes / 5000, 1), 6),
          curveness: 0.2,
          opacity: 0.6,
        },
      }));

      // 6. Render the Chart (Adding 'true' to force a clean re-render)
      this.conversationsChart.setOption(
        {
          tooltip: {
            trigger: "item",
            formatter: (params) => {
              if (params.dataType === "edge") {
                const kb = (params.data.bytes / 1024).toFixed(2);
                return `
                <div style="font-weight:bold;">${params.data.source} ➔ ${params.data.target}</div>
                <hr style="margin:4px 0; border-color:#ccc;"/>
                Data Transferred: <b style="color:#10b981;">${kb} KB</b><br/>
                Protocols: <b>${params.data.protocols}</b>
              `;
              }
              return `<b>IP Address:</b> ${params.name}`;
            },
          },
          series: [
            {
              type: "graph",
              layout: "force",
              data: nodes,
              links: links, // Changed 'edges' to 'links' for strict ECharts compatibility
              roam: true,
              edgeSymbol: ["none", "arrow"],
              edgeSymbolSize: [0, 8],
              force: {
                repulsion: 150, // Lower repulsion keeps nodes closer together
                edgeLength: 80,
                gravity: 0.1, // Pulls nodes towards the center of the div
                friction: 0.2, // Helps nodes settle down faster
              },
            },
          ],
        },
        true
      );
    },
    downloadAnalytics(format) {
      let url = `${this.apiUrl}/v1/network/export?start_time=${this.startTimestamp}&end_time=${this.endTimestamp}&format=${format}`;

      if (this.exportLimit && this.exportLimit > 0) {
        url += `&limit=${this.exportLimit}`;
      }

      // We don't need a specific filename here because the backend enforces
      // the Content-Disposition header with the timestamped filename.
      const link = document.createElement("a");
      link.href = url;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
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
      const k = 1024;
      const sizes = ["B", "KB", "MB", "GB", "TB"];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    },
    getRoleColor(role) {
      const colors = {
        gNB: "blue",
        AMF: "purple",
        UE: "green",
        NEAR_RT_RIC: "orange",
        Unidentified: "grey",
      };
      return colors[role] || "primary";
    },
    async fetchData() {
      await Promise.all([this.fetchStatistics(), this.fetchRoles()]);
    },
    async fetchStatistics(showLoader = true) {
      if (showLoader) this.loading = true;
      try {
        const url = `${this.apiUrl}/v1/network/statistics?start_time=${this.startTimestamp}&end_time=${this.endTimestamp}&format=json&limit=5000`;
        const res = await fetch(url, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
          },
        });
        if (!res.ok) throw new Error("Failed to fetch statistics");

        this.stats = (await res.json()).reverse();

        this.updateCharts();

        // NEW: Render the topology graph once on initial load
        this.$nextTick(() => {
          if (this.stats.length > 0) {
            this.renderConversationsChart();
          }
        });
      } catch (err) {
        if (showLoader)
          this.showSnackbar("Could not load network statistics.", "error");
      } finally {
        if (showLoader) this.loading = false;
      }
    },
    async fetchRoles() {
      this.loadingRoles = true;
      try {
        const url = `${this.apiUrl}/v1/network/roles/latest?format=json`;
        const res = await fetch(url, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
          },
        });
        if (!res.ok) throw new Error("Failed to fetch roles");
        this.roles = await res.json();
      } catch (err) {
        this.showSnackbar("Could not load latest role snapshot.", "error");
      } finally {
        this.loadingRoles = false;
      }
    },
    renderTrendChart() {
      const dom = document.getElementById("trend-chart");
      if (!dom) return;
      if (!this.trendChart) this.trendChart = echarts.init(dom);

      // Extract time and bytes (simplistic timeline mapping)
      const times = this.stats.map((s) =>
        new Date(s.ts * 1000).toLocaleTimeString()
      );
      const bytesOut = this.stats.map((s) => s.orig_bytes || 0);
      const bytesIn = this.stats.map((s) => s.resp_bytes || 0);

      this.trendChart.setOption({
        tooltip: { trigger: "axis" },
        legend: { data: ["Bytes Out", "Bytes In"] },
        xAxis: { type: "category", data: times, boundaryGap: false },
        yAxis: {
          type: "value",
          axisLabel: { formatter: (val) => this.formatBytes(val) },
        },
        series: [
          {
            name: "Bytes Out",
            type: "line",
            data: bytesOut,
            smooth: true,
            itemStyle: { color: "#3b82f6" },
            areaStyle: { opacity: 0.1 },
          },
          {
            name: "Bytes In",
            type: "line",
            data: bytesIn,
            smooth: true,
            itemStyle: { color: "#10b981" },
            areaStyle: { opacity: 0.1 },
          },
        ],
      });
    },
    renderStateChart() {
      const dom = document.getElementById("state-chart");
      if (!dom) return;
      if (!this.stateChart) this.stateChart = echarts.init(dom);

      const stateCounts = {};
      this.stats.forEach((s) => {
        const state = s.conn_state || "Unknown";
        stateCounts[state] = (stateCounts[state] || 0) + 1;
      });

      const data = Object.entries(stateCounts).map(([name, value]) => ({
        name,
        value,
      }));

      this.stateChart.setOption({
        tooltip: { trigger: "item" },
        legend: { bottom: "0" },
        series: [
          {
            name: "Connection State",
            type: "pie",
            radius: ["40%", "70%"],
            itemStyle: {
              borderRadius: 10,
              borderColor: "#fff",
              borderWidth: 2,
            },
            data: data,
          },
        ],
      });
    },
    renderProtocolChart() {
      const dom = document.getElementById("protocol-chart");
      if (!dom) return;
      if (!this.protoChart) this.protoChart = echarts.init(dom);

      const protoCounts = {};
      this.stats.forEach((s) => {
        const p = s.proto || "unknown";
        protoCounts[p] = (protoCounts[p] || 0) + 1;
      });

      const data = Object.entries(protoCounts).map(([name, value]) => ({
        name: name.toUpperCase(),
        value,
      }));

      this.protoChart.setOption({
        tooltip: { trigger: "item" },
        legend: { bottom: "0" },
        series: [
          {
            name: "Protocol",
            type: "pie",
            radius: "70%",
            itemStyle: { borderRadius: 5, borderColor: "#fff", borderWidth: 2 },
            data: data,
          },
        ],
      });
    },
    renderTopTalkersChart() {
      const dom = document.getElementById("top-talkers-chart");
      if (!dom) return;
      if (!this.topTalkersChart) this.topTalkersChart = echarts.init(dom);

      const talkers = {};
      this.stats.forEach((s) => {
        const ip = s["id.orig_h"];
        talkers[ip] = (talkers[ip] || 0) + (parseInt(s.orig_bytes) || 0);
      });

      const sorted = Object.entries(talkers)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

      this.topTalkersChart.setOption({
        tooltip: {
          trigger: "axis",
          formatter: (params) =>
            `${params[0].name}: ${this.formatBytes(params[0].value)}`,
        },
        xAxis: { type: "value", show: false },
        yAxis: { type: "category", data: sorted.map((i) => i[0]).reverse() },
        series: [
          {
            data: sorted.map((i) => i[1]).reverse(),
            type: "bar",
            itemStyle: { color: "#8b5cf6", borderRadius: [0, 5, 5, 0] },
          },
        ],
      });
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
      const url = `${this.apiUrl}/v1/network/pcap/headers?start_time=${this.startTimestamp}&end_time=${this.endTimestamp}`;
      this.triggerDownload(url, `headers_${this.startTimestamp}.pcap`);
    },
    downloadFullPcap() {
      const url = `${this.apiUrl}/v1/network/pcap/latest/full`;
      this.triggerDownload(url, `full_payload_latest.pcap`);
    },
    triggerDownload(url, filename) {
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
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
</style>
