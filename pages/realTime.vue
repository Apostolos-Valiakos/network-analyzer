<template>
  <div class="futuristic-light-container">
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
        @click="stopCaptureAndDownload"
        :disabled="!isConnected || !isCapturing || isGenerating"
        color="primary"
        size="large"
        variant="flat"
        class="control-btn"
        prepend-icon="mdi-download"
      >
        {{ isGenerating ? "Finalizing PCAP..." : "Generate PCAP" }}
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
              :disabled="!isConnected || !isCapturing || isGenerating"
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
              :disabled="!totalPacketsCaptured || isSendingPcap"
              @click="startClustering()"
              color="blue"
              size="large"
              variant="flat"
              class="control-btn mb-4"
              prepend-icon="mdi-chart-areaspline"
            >
              Analyze
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
      wsUrl: process.env.VUE_APP_WS_URL || "ws://127.0.0.1:5001",
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
            // NOTE: sessionId is now set in startCapture() to prevent race conditions.
            // We only reset UI elements if they weren't already reset.
            if (
              this.totalPacketsCaptured > 0 &&
              this.uploadQueue.length === 0
            ) {
              // This implies a restart from another client or glitch, safe to sync
            }
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

          // Only log if session ID exists
          if (this.sessionId) {
            fetch(`${this.apiUrl}/log-packet`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                session_id: this.sessionId,
                src_ip: srcIp,
                dst_ip: dstIp,
                protocol: protocol,
                size: size,
              }),
            }).catch((err) => console.error("Log error:", err));
          }
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
        const res = await fetch(`${this.apiUrl}/save-pcap`, {
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

    stopCaptureAndDownload() {
      this.sendControlCommand("STOP_CAPTURE");
      this.isGenerating = true;
      setTimeout(() => this.flushUploadQueue(true), 500);
    },

    async handleVisualizeNetwork() {
      this.isGraphLoading = true;
      if (!this.filename) await this.flushUploadQueue(true);

      let retries = 0;
      while (!this.filename && retries < 5) {
        await new Promise((r) => setTimeout(r, 1000));
        retries++;
      }

      const res = await fetch(
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
    },
    clearPackets() {
      this.totalPacketsCaptured = 0;
      this.lastPackets = [];
      this.liveNodes.clear();
      this.liveLinks = [];
      this.graphData = null;
    },
    startClustering() {
      this.$router.push({ name: "clustering", query: { id: this.filename } });
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
.futuristic-light-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
  background-color: #f0f4f8;
  font-family: "Inter", sans-serif;
  border-radius: 20px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.05);
}

.realtime-view {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 24px;
  padding: 16px;
  border: 1px dashed #3b82f644;
  border-radius: 16px;
}

.status-card {
  border: 1px solid #d1e5ff;
  background-color: #f7faff !important;
  border-radius: 16px;
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.05);
}

.data-card {
  border: 1px solid #e2e8f0;
  background-color: white !important;
  border-radius: 16px;
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
  background-color: #f7faff;
  border: 1px solid #e0f2fe;
  padding: 12px;
  border-radius: 12px;
  margin-bottom: 8px;
}

.metric-label {
  font-size: 0.8rem;
  color: #64748b;
  font-weight: 500;
  margin-bottom: 4px;
}

.metric-value {
  font-size: 1.5rem;
  font-weight: 800;
  color: #1e40af;
}

.packet-list {
  background-color: #f7faff;
  border-radius: 12px;
  padding: 8px;
}

.packet-item {
  border-bottom: 1px solid #e0f2fe;
  padding: 8px 0;
}
.packet-item:last-child {
  border-bottom: none;
}
.font-mono {
  font-family: monospace;
}

/* NEW: Style for gap in interface controls */
.gap-3 {
  gap: 12px;
}
</style>
