<template>
  <div class="dark-page-container">
    <v-snackbar v-model="snackbar" :color="snackbarType" timeout="3000">
      {{ snackbarText }}
      <template v-slot:action="{ attrs }">
        <v-btn color="white" text v-bind="attrs" @click="snackbar = false">
          Close
        </v-btn>
      </template>
    </v-snackbar>

    <SnapshotBar
      :disabled="!isConnected || !isCapturing || isGenerating"
      :generating="isGenerating"
      :download-link="downloadLink"
      :filename="filename"
      @generate="generateSnapshot"
    />

    <ConnectionCard :connected="isConnected" :url.sync="wsUrl" @connect="connect" />

    <v-row>
      <v-col cols="12" md="6">
        <CaptureControls
          :connected="isConnected"
          :capturing="isCapturing"
          :generating="isGenerating"
          :sending="isSendingPcap"
          :packet-count="totalPacketsCaptured"
          :interfaces="availableInterfaces"
          :selected-interface="selectedInterface"
          :current-interface="currentInterface"
          @get-interfaces="getInterfaces"
          @select-interface="onSelectInterface"
          @start="startCapture"
          @stop="stopCapture"
          @clear="clearPackets"
          @visualize="handleVisualizeNetwork"
          @analyze="analyzeCapture"
        />
      </v-col>

      <v-col cols="12" md="6">
        <CaptureMetrics :packet-count="totalPacketsCaptured" :total-bytes="totalBytesCaptured" />
      </v-col>
    </v-row>

    <v-row class="mt-6">
      <v-col cols="12" md="6">
        <PacketLog :packets="lastPackets" />
      </v-col>
      <v-col cols="12" md="6">
        <GraphPreview :graph-data="graphData" :loading="isGraphLoading" :graph-key="graphKey" />
      </v-col>
    </v-row>
  </div>
</template>

<script>
import CaptureControls from "@/components/realtime/CaptureControls.vue";
import CaptureMetrics from "@/components/realtime/CaptureMetrics.vue";
import ConnectionCard from "@/components/realtime/ConnectionCard.vue";
import GraphPreview from "@/components/realtime/GraphPreview.vue";
import PacketLog from "@/components/realtime/PacketLog.vue";
import SnapshotBar from "@/components/realtime/SnapshotBar.vue";
import { base64Size, generateSessionId, ipv4Endpoints } from "@/utils/realtime";

// The page owns the WebSocket to publisher.py and the capture state; the
// components in components/realtime/ show it and report the user's actions.
export default {
  components: {
    CaptureControls,
    CaptureMetrics,
    ConnectionCard,
    GraphPreview,
    PacketLog,
    SnapshotBar,
  },
  data() {
    return {
      wsUrl: process.env.WS_URL || "ws://127.0.0.1:5002",
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
  methods: {
    generateUniqueId() {
      return generateSessionId();
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
      const len = base64Size(base64Packet);
      this.totalPacketsCaptured++;
      this.totalBytesCaptured += len;

      // 1. Parse & Update Graph / DB Logs
      this.parseAndLogPacket(base64Packet);

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

    parseAndLogPacket(base64Str) {
      const endpoints = ipv4Endpoints(base64Str);
      if (endpoints) this.updateLiveGraph(endpoints.src, endpoints.dst);
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
        const data = await this.$api.json(
          `/save-pcap`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              session_id: this.sessionId,
              packets: chunk,
              is_final_chunk: isFinal,
            }),
          },
          "Saving the capture failed"
        );
        if (isFinal && data.filename) {
          this.filename = data.filename;
          this.downloadLink = this.$api.url(`/generated_pcaps/${this.filename}`);
          this.showSnackbar("PCAP Generated Successfully", "success");
          this.isGenerating = false;
        }
      } catch (e) {
        console.error("Upload failed", e);
        if (isFinal) {
          this.showSnackbar(e.message, "error");
          this.isGenerating = false;
        }
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

      try {
        const data = await this.$api.json(
          `/analyze-saved-pcap/${this.filename}`,
          {},
          "Could not build the network graph"
        );
        this.graphData = data.analysis.graph;
      } catch (e) {
        this.showSnackbar(e.message, "error");
      } finally {
        this.isGraphLoading = false;
      }
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
    onSelectInterface(value) {
      this.selectedInterface = value;
      this.setCaptureInterface();
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
</style>
