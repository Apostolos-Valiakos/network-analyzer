<template>
  <div class="dark-page-container">
    <v-snackbar v-model="snackbar" :color="snackbarType" timeout="3000">
      {{ snackbarText }}
      <template v-slot:actions>
        <v-btn color="white" variant="text" @click="snackbar = false">
          Close
        </v-btn>
      </template>
    </v-snackbar>

    <div class="realtime-view">
      <v-btn
        @click="generateSnapshot"
        :disabled="!isConnected || !isCapturing || isGenerating"
        color="primary"
        size="large"
        variant="flat"
        class="control-btn"
        prepend-icon="mdi-download"
      >
        {{ isGenerating ? "Saving snapshot..." : "Generate PCAP" }}
      </v-btn>
      <div v-if="downloadLink" class="mt-2">
        <a :href="downloadLink" :download="filename">Download PCAP</a>
      </div>
    </div>

    <v-card class="status-card mb-6" elevation="0">
      <v-card-text class="pa-4">
        <div class="d-flex align-center justify-space-between">
          <div class="d-flex align-center">
            <v-icon
              :color="isConnected ? 'success' : 'error'"
              class="mr-3"
              size="28"
            >
              {{ isConnected ? "mdi-link" : "mdi-link-off" }}
            </v-icon>
            <div class="text-h6 font-weight-bold">
              Connection Status:
              <span :class="isConnected ? 'text-success' : 'text-error'">
                {{ isConnected ? "Connected" : "Disconnected" }}
              </span>
            </div>
          </div>
          <v-btn
            @click="connect"
            :disabled="isConnected"
            color="secondary"
            variant="tonal"
          >
            Connect
          </v-btn>
        </div>
        <v-text-field
          v-model="wsUrl"
          label="WebSocket URL"
          :disabled="isConnected"
          density="compact"
          variant="outlined"
          class="mt-4"
          prepend-icon="mdi-web"
          hide-details
        ></v-text-field>
      </v-card-text>
    </v-card>

    <v-row>
      <v-col cols="12" md="6">
        <v-card class="data-card pa-4" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
            Capture Controls
          </v-card-title>
          <div class="d-flex align-center mb-4 gap-3">
            <v-btn
              @click="getInterfaces"
              :disabled="!isConnected"
              color="info"
              variant="flat"
              prepend-icon="mdi-network-outline"
              class="control-btn"
            >
              Get Interfaces
            </v-btn>
            <v-select
              v-model="selectedInterface"
              :items="availableInterfaces"
              label="Select Interface"
              density="compact"
              variant="outlined"
              :disabled="
                !isConnected || isCapturing || availableInterfaces.length === 0
              "
              class="flex-grow-1"
              hide-details
              @update:model-value="setCaptureInterface"
            ></v-select>
          </div>

          <div class="controls-section">
            <v-btn
              @click="startCapture"
              :disabled="
                !isConnected || isCapturing || isGenerating || !currentInterface
              "
              color="green"
              variant="flat"
              class="control-btn"
              prepend-icon="mdi-play-circle-outline"
            >
              Start
            </v-btn>
            <v-btn
              @click="stopCapture"
              :disabled="!isConnected || isGenerating"
              color="orange"
              variant="flat"
              class="control-btn"
              prepend-icon="mdi-stop-circle-outline"
            >
              Stop
            </v-btn>
            <v-btn
              @click="clearPackets"
              :disabled="isCapturing || isGenerating"
              color="red"
              variant="tonal"
              class="control-btn"
              prepend-icon="mdi-delete-outline"
            >
              Clear
            </v-btn>
            <v-btn
              @click="handleVisualizeNetwork"
              :disabled="!totalPacketsCaptured || isSendingPcap"
              color="purple"
              size="large"
              variant="flat"
              class="control-btn white--text"
              prepend-icon="mdi-network-outline"
            >
              Visualize
            </v-btn>
            <v-btn
              :disabled="!totalPacketsCaptured || isSendingPcap || isGenerating"
              @click="analyzeCapture"
              color="blue"
              size="large"
              variant="flat"
              class="control-btn mb-4"
              prepend-icon="mdi-chart-areaspline"
            >
              {{ isGenerating ? "Preparing..." : "Analyze" }}
            </v-btn>
          </div>
        </v-card>
      </v-col>

      <v-col cols="12" md="6">
        <v-card class="data-card pa-4" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
            Real-Time Metrics
          </v-card-title>
          <v-row dense>
            <v-col cols="6">
              <div class="metric-box">
                <div class="metric-label">Packets Captured</div>
                <div class="metric-value">{{ totalPacketsCaptured }}</div>
              </div>
            </v-col>
            <v-col cols="6">
              <div class="metric-box">
                <div class="metric-label">Total Size (MB)</div>
                <div class="metric-value">{{ totalDataSizeMb }}</div>
              </div>
            </v-col>
          </v-row>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-6">
      <v-col cols="12" md="6">
        <v-card class="pa-4 data-card" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
            Packet Log (Last 10)
          </v-card-title>
          <v-list dense class="packet-list">
            <v-list-item
              v-for="(packet, index) in lastPackets"
              :key="index"
              class="packet-item"
            >
              <v-list-item-title class="text-caption font-mono">
                {{ packet.timestamp }} - {{ packet.length }} bytes
              </v-list-item-title>
              <v-list-item-subtitle class="text-truncate text-monospace">
                {{ packet.preview }}
              </v-list-item-subtitle>
            </v-list-item>
          </v-list>
        </v-card>
      </v-col>
      <v-col cols="12" md="6">
        <v-card class="pa-4 data-card" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
            Network Graph (Preview)
          </v-card-title>
          <v-card-text class="pa-4 text-center">
            <v-skeleton-loader
              v-if="isGraphLoading"
              type="image"
              height="300"
            />
            <NetworkGraph
              v-if="graphData && !isGraphLoading"
              :graphData="graphData"
              :key="graphKey"
            />
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import NetworkGraph from "@/components/NetworkGraph.vue";

export default {
  components: { NetworkGraph },
  data() {
    return {
      wsUrl: process.env.WS_URL || "ws://127.0.0.1:5002",
      apiUrl: process.env.VUE_APP_API_BASE_URL || "http://127.0.0.1:5555",
      chunkSize: 500,

      // State
      client: null,
      isConnected: false,
      isCapturing: false,
      isGenerating: false,

      // Buffers
      visualizationBuffer: [],
      uploadQueue: [],
      sessionId: null,

      // Real-time Graph State
      liveNodes: new Set(),
      liveLinks: [],

      // Metrics
      totalPacketsCaptured: 0,
      totalBytesCaptured: 0,

      // UI
      availableInterfaces: [],
      selectedInterface: null,
      currentInterface: null,
      snackbar: false,
      snackbarText: "",
      snackbarType: "info",
      lastPackets: [],
      filename: null,
      downloadLink: null,
      graphData: null,
      graphKey: 0,
      isGraphLoading: false,
      isSendingPcap: false,
    };
  },
  computed: {
    totalDataSizeMb() {
      return (this.totalBytesCaptured / (1024 * 1024)).toFixed(2);
    },
  },
  methods: {
    generateUniqueId() {
      return (
        "session_" +
        Math.random().toString(36).substring(2, 9) +
        Date.now().toString(36)
      );
    },

    // --- WebSocket Logic ---
    connect() {
      if (this.client) this.client.close();
      this.client = new WebSocket(this.wsUrl);

      this.client.onopen = () => {
        this.isConnected = true;
        this.showSnackbar("Connected to Sniffer", "success");
        this.getInterfaces();
      };

      this.client.onmessage = (event) => {
        const msg = JSON.parse(event.data);

        if (msg.type === "STATUS") {
          if (msg.status === "CAPTURE_STARTED") {
            this.isCapturing = true;
          }
          if (msg.status === "CAPTURE_STOPPED") {
            this.isCapturing = false;
          }
          if (msg.current_interface)
            this.currentInterface = msg.current_interface;
        } else if (msg.type === "INTERFACE_LIST") {
          this.availableInterfaces = Object.keys(msg.interfaces);
          this.currentInterface =
            msg.current_interface || this.availableInterfaces[0];
          this.selectedInterface = this.currentInterface;
        } else if (msg.type === "PACKET_DATA") {
          this.processPacket(msg.packet);
        }
      };
    },

    processPacket(base64Packet) {
      const len = Math.floor((base64Packet.length * 3) / 4);
      this.totalPacketsCaptured++;
      this.totalBytesCaptured += len;

      // 1. Parse & Update Graph / DB Logs
      this.parseAndLogPacket(base64Packet, len);

      // 2. Buffer for PCAP
      this.uploadQueue.push(base64Packet);
      if (this.uploadQueue.length >= this.chunkSize) {
        this.flushUploadQueue(false);
      }

      // 3. Update Log UI
      if (this.lastPackets.length < 10 || this.totalPacketsCaptured % 5 === 0) {
        this.lastPackets.unshift({
          timestamp: new Date().toLocaleTimeString(),
          length: len,
          preview: "Data captured...",
        });
        if (this.lastPackets.length > 10) this.lastPackets.pop();
      }
    },

    updateLiveGraph(srcIp, dstIp) {
      this.liveNodes.add(srcIp);
      this.liveNodes.add(dstIp);
      this.liveLinks.push({ source: srcIp, target: dstIp });

      if (this.totalPacketsCaptured % 5 !== 0) return;

      const nodesArray = Array.from(this.liveNodes).map((ip) => ({
        name: ip,
        category: 0,
        draggable: true,
      }));

      this.graphData = {
        nodes: nodesArray,
        links: this.liveLinks,
        categories: [{ name: "Live Devices" }],
      };
    },

    parseAndLogPacket(base64Str, size) {
      try {
        const binaryString = atob(base64Str);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }

        if (bytes[12] === 0x08 && bytes[13] === 0x00) {
          const ipOffset = 14;
          const protocolMap = { 6: "TCP", 17: "UDP", 1: "ICMP" };
          const protocolNum = bytes[ipOffset + 9];
          const protocol = protocolMap[protocolNum] || "Other";
          const srcIp = `${bytes[ipOffset + 12]}.${bytes[ipOffset + 13]}.${
            bytes[ipOffset + 14]
          }.${bytes[ipOffset + 15]}`;
          const dstIp = `${bytes[ipOffset + 16]}.${bytes[ipOffset + 17]}.${
            bytes[ipOffset + 18]
          }.${bytes[ipOffset + 19]}`;

          this.updateLiveGraph(srcIp, dstIp);
        }
      } catch (e) {
        // Ignore parsing errors
      }
    },

    async flushUploadQueue(isFinal = false) {
      if (this.uploadQueue.length === 0 && !isFinal) return;

      // SAFETY CHECK: Prevent 400 Errors
      if (!this.sessionId) {
        console.error("Skipping upload: No Session ID initialized yet.");
        // We do NOT clear the queue here, so data is preserved until ID is ready
        return;
      }

      const chunk = [...this.uploadQueue];
      this.uploadQueue = [];

      try {
        const res = await this.$apiFetch(`${this.apiUrl}/save-pcap`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: this.sessionId,
            packets: chunk,
            is_final_chunk: isFinal,
          }),
        });
        const data = await res.json();
        if (isFinal && data.filename) {
          this.filename = data.filename;
          this.downloadLink = `${this.apiUrl}/generated_pcaps/${this.filename}`;
          this.showSnackbar("PCAP Generated Successfully", "success");
          this.isGenerating = false;
        }
      } catch (e) {
        console.error("Upload failed", e);
      }
    },

    // Snapshot: finalize current buffer as a PCAP, keep capture running
    async generateSnapshot() {
      if (this.isGenerating) return;
      this.isGenerating = true;
      await this.flushUploadQueue(true);
      // Start a fresh accumulation session for the ongoing capture
      this.sessionId = this.generateUniqueId();
      this.uploadQueue = [];
    },

    // Stop capture, finalize PCAP, navigate to clustering
    async analyzeCapture() {
      if (this.isGenerating) return;
      this.isGenerating = true;
      this.sendControlCommand("STOP_CAPTURE");
      this.isCapturing = false;
      await this.flushUploadQueue(true);
      if (!this.filename) {
        this.showSnackbar("Failed to generate PCAP for analysis", "error");
        this.isGenerating = false;
        return;
      }
      this.$router.push({ path: "/clustering", query: { id: this.filename } });
    },

    async handleVisualizeNetwork() {
      this.isGraphLoading = true;
      if (!this.filename) await this.flushUploadQueue(true);

      let retries = 0;
      while (!this.filename && retries < 5) {
        await new Promise((r) => setTimeout(r, 1000));
        retries++;
      }

      const res = await this.$apiFetch(
        `${this.apiUrl}/analyze-saved-pcap/${this.filename}`
      );
      const data = await res.json();
      this.graphData = data.analysis.graph;
      this.isGraphLoading = false;
    },

    sendControlCommand(cmd) {
      if (this.client) this.client.send(JSON.stringify({ command: cmd }));
    },
    getInterfaces() {
      this.sendControlCommand("GET_INTERFACES");
    },

    // CRITICAL FIX: Initialize Session ID immediately on user click
    startCapture() {
      this.sessionId = this.generateUniqueId();
      this.totalPacketsCaptured = 0;
      this.totalBytesCaptured = 0;
      this.uploadQueue = [];
      this.liveNodes.clear();
      this.liveLinks = [];
      this.graphData = null;

      this.sendControlCommand("START_CAPTURE");
    },

    stopCapture() {
      this.sendControlCommand("STOP_CAPTURE");
      this.isCapturing = false;
    },
    clearPackets() {
      this.totalPacketsCaptured = 0;
      this.lastPackets = [];
      this.liveNodes.clear();
      this.liveLinks = [];
      this.graphData = null;
    },
    startClustering() {
      if (this.filename) {
        this.$router.push({ path: "/clustering", query: { id: this.filename } });
      }
    },
    showSnackbar(text, type) {
      this.snackbarText = text;
      this.snackbarType = type;
      this.snackbar = true;
    },
    setCaptureInterface() {
      if (
        !this.selectedInterface ||
        this.selectedInterface === this.currentInterface
      )
        return;
      if (this.isCapturing) {
        this.showSnackbar(
          "Please STOP the capture before changing the interface.",
          "error"
        );
        this.selectedInterface = this.currentInterface;
        return;
      }
      if (this.client && this.client.readyState === WebSocket.OPEN) {
        this.client.send(
          JSON.stringify({
            command: "SET_INTERFACE",
            interface: this.selectedInterface,
          })
        );
      }
    },
  },
};
</script>

<style scoped>
.dark-page-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.realtime-view {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 24px;
  padding: 16px;
  border: 1px dashed var(--highlight-border);
  border-radius: 16px;
  background: var(--highlight-bg);
}

.status-card {
  border: 1px solid var(--accent-border) !important;
  background-color: var(--surface) !important;
  border-radius: 16px !important;
}

.data-card {
  border: 1px solid var(--border) !important;
  background-color: var(--surface) !important;
  border-radius: 16px !important;
}

.controls-section {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.control-btn {
  border-radius: 16px !important;
  font-weight: 700;
  text-transform: none;
  letter-spacing: 0.5px;
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

.packet-list {
  background-color: var(--highlight-bg);
  border-radius: 12px;
  padding: 8px;
}

.packet-item {
  border-bottom: 1px solid var(--packet-item-border);
  padding: 8px 0;
}
.packet-item:last-child {
  border-bottom: none;
}
.font-mono {
  font-family: monospace;
}

.gap-3 {
  gap: 12px;
}
</style>
