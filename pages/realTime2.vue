<template>
  <div class="futuristic-light-container">
    <!-- Snackbar for all user notifications -->
    <v-snackbar v-model="snackbar" :color="snackbarType" timeout="3000">
      {{ snackbarText }}
      <template v-slot:actions>
        <v-btn color="white" variant="text" @click="snackbar = false"
          >Close</v-btn
        >
      </template>
    </v-snackbar>

    <!-- Generate PCAP Button and Download Link -->
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
        {{ isGenerating ? "Generating PCAP..." : "Generate PCAP" }}
      </v-btn>
      <div v-if="downloadLink" class="mt-2">
        <a :href="downloadLink" :download="filename">Download PCAP</a>
      </div>
    </div>

    <!-- WebSocket Connection Status Card -->
    <v-card class="status-card mb-6" elevation="0">
      <v-card-text class="pa-4">
        <div class="d-flex align-center justify-space-between">
          <div class="d-flex align-center">
            <v-icon
              :color="isConnected ? 'success' : 'error'"
              class="mr-3"
              size="28"
              >{{ isConnected ? "mdi-link" : "mdi-link-off" }}</v-icon
            >
            <div class="text-h6 font-weight-bold">
              Connection Status:
              <span :class="isConnected ? 'text-success' : 'text-error'">{{
                isConnected ? "Connected" : "Disconnected"
              }}</span>
            </div>
          </div>
          <v-btn
            @click="connect"
            :disabled="isConnected"
            color="secondary"
            variant="tonal"
            >Reconnect</v-btn
          >
        </div>
        <div class="mt-2 text-caption text-medium-emphasis">
          WebSocket Publisher: {{ wsUrl }}
        </div>
      </v-card-text>
    </v-card>

    <!-- Controls and Metrics -->
    <v-row>
      <v-col cols="12" md="6">
        <v-card class="data-card pa-4" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
            Capture Controls
          </v-card-title>
          <div class="controls-section">
            <v-btn
              @click="startCapture"
              :disabled="!isConnected || isCapturing || isGenerating"
              color="green"
              variant="flat"
              class="control-btn"
              prepend-icon="mdi-play-circle-outline"
            >
              Start Capture
            </v-btn>

            <v-btn
              @click="stopCapture"
              :disabled="!isConnected || !isCapturing || isGenerating"
              color="orange"
              variant="flat"
              class="control-btn"
              prepend-icon="mdi-stop-circle-outline"
            >
              Stop Capture
            </v-btn>

            <v-btn
              @click="clearPackets"
              :disabled="isCapturing || isGenerating"
              color="red"
              variant="tonal"
              class="control-btn"
              prepend-icon="mdi-delete-outline"
            >
              Clear Buffer ({{ rawPackets.length }})
            </v-btn>

            <v-btn
              @click="handleVisualizeNetwork"
              :disabled="!rawPackets.length || isSendingPcap"
              color="purple"
              size="large"
              variant="flat"
              class="control-btn white--text"
              prepend-icon="mdi-network-outline"
            >
              Visualize Network
            </v-btn>

            <v-btn
              :disabled="!rawPackets.length || isSendingPcap"
              @click="startClustering()"
              color="blue"
              size="large"
              variant="flat"
              class="control-btn mb-4"
              prepend-icon="mdi-chart-areaspline"
            >
              Start Analysis
            </v-btn>
          </div>
        </v-card>
      </v-col>

      <v-col cols="12" md="6">
        <v-card class="data-card pa-4" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3"
            >Real-Time Metrics</v-card-title
          >
          <v-row dense>
            <v-col cols="6">
              <div class="metric-box">
                <div class="metric-label">Packets Captured</div>
                <div class="metric-value">{{ rawPackets.length }}</div>
              </div>
            </v-col>
            <v-col cols="6">
              <div class="metric-box">
                <div class="metric-label">Packets/Sec (Avg)</div>
                <div class="metric-value">{{ packetsPerSecond }}</div>
              </div>
            </v-col>
            <v-col cols="6">
              <div class="metric-box">
                <div class="metric-label">Total Size (MB)</div>
                <div class="metric-value">{{ totalDataSizeMb }}</div>
              </div>
            </v-col>
            <v-col cols="6">
              <div class="metric-box">
                <div class="metric-label">Capture State</div>
                <div
                  class="metric-value"
                  :class="isCapturing ? 'text-success' : 'text-warning'"
                >
                  {{ isCapturing ? "Active" : "Paused" }}
                </div>
              </div>
            </v-col>
          </v-row>
        </v-card>
      </v-col>
    </v-row>

    <!-- Packet Log + Network Graph Side-by-Side -->
    <v-row class="mt-6">
      <!-- Packet Log -->
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
                {{ packet.timestamp }} - Length: {{ packet.length }} bytes
              </v-list-item-title>
              <v-list-item-subtitle class="text-truncate text-monospace">
                {{ packet.preview }}
              </v-list-item-subtitle>
            </v-list-item>
            <v-list-item
              v-if="!lastPackets.length"
              class="text-center text-medium-emphasis"
            >
              <v-list-item-title>No packets captured yet.</v-list-item-title>
            </v-list-item>
          </v-list>
        </v-card>
      </v-col>

      <!-- Network Graph -->
      <v-col cols="12" md="6">
        <v-card class="pa-4 data-card" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
            Network Graph
          </v-card-title>

          <v-card-text class="pa-4 text-center">
            <!-- Skeleton while loading -->
            <v-skeleton-loader
              v-if="isGraphLoading"
              type="image"
              class="mx-auto"
              max-width="400"
              height="300"
            />

            <!-- NetworkGraph rendered when ready -->
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
  components: {
    NetworkGraph,
  },
  data() {
    return {
      // Configuration
      wsUrl: "ws://127.0.0.1:5001", // WebSocket Publisher
      apiUrl: "http://127.0.0.1:5000", // Flask API Server
      chunkSize: 1000, // Number of packets to send per HTTP chunk

      // State
      client: null, // WebSocket client instance
      isConnected: false,
      isCapturing: false,
      isGenerating: false,
      rawPackets: [], // Stores ArrayBuffer/Uint8Array packets (Base64 is NOT stored here)
      sessionId: null, // Manages the chunked upload session ID

      // UI/Metrics
      snackbar: false,
      snackbarText: "",
      snackbarType: "info",
      packetsLastSecond: 0,
      packetsPerSecond: 0,
      lastPackets: [], // For display log
      totalDataSize: 0, // In bytes
      filename: null,
      downloadLink: null,
      reconnectInterval: null,

      //Network Grpah
      isSendingPcap: false,
      graphData: null,
      graphKey: 0,
      isGraphLoading: false,
    };
  },
  computed: {
    totalDataSizeMb() {
      return (this.totalDataSize / (1024 * 1024)).toFixed(2);
    },
  },
  mounted() {
    //  // Start connection attempt on mount
    // this.connect();
  },
  beforeDestroy() {
    // Clean up interval and close connection
    clearInterval(this.reconnectInterval);
    if (this.client) {
      this.client.close();
    }
  },
  methods: {
    async handleVisualizeNetwork() {
      try {
        // Pause live capture
        if (this.isConnected) {
          console.log("Pausing live capture...");
          this.stopCaptureAndDownload();
        }

        // Reset graph and show skeleton
        this.isGraphLoading = true;
        this.graphData = null;
        this.graphKey++;

        // Generate PCAP from captured data
        await this.generatePcap();

        // Send file for analysis
        const response = await fetch(
          `${this.apiUrl}/analyze-saved-pcap/${this.filename}`
        );
        const data = await response.json();

        if (response.ok) {
          this.graphData = data.analysis.graph;
          this.graphKey++;
          this.showSnackbar("Network graph generated successfully!", "success");
        } else {
          this.showSnackbar(`Analysis failed: ${data.error}`, "error");
          console.error("Analysis error:", data.error);
        }
      } catch (err) {
        this.showSnackbar(`Visualization failed: ${err.message}`, "error");
        console.error("Visualization error:", err);
      } finally {
        this.isGraphLoading = false;
        // Resume capture automatically
        if (this.isConnected) {
          console.log("Resuming live capture...");
          this.startCapture();
        }
      }
    },
    // --- Utility Methods ---
    showSnackbar(text, type = "info") {
      this.snackbarText = text;
      this.snackbarType = type;
      this.snackbar = true;
    },

    generateUniqueId() {
      return (
        "pcap_" +
        Math.random().toString(36).substring(2, 9) +
        Date.now().toString(36)
      );
    },

    updateMetrics() {
      this.packetsPerSecond = this.packetsLastSecond;
      this.packetsLastSecond = 0;
    },

    // --- WebSocket Connection ---
    connect() {
      setInterval(this.updateMetrics, 1000);
      if (this.client && this.client.readyState === WebSocket.OPEN) {
        this.client.close();
      }

      console.log(`Attempting to connect to ${this.wsUrl}...`);
      this.client = new WebSocket(this.wsUrl);
      this.isConnected = false;
      this.showSnackbar("Connecting to WebSocket Publisher...", "info");

      this.client.onopen = () => {
        this.isConnected = true;
        this.showSnackbar("Connected to WebSocket Publisher.", "success");
        console.log("WebSocket connection established.");
        // Stop any pending reconnect attempts
        if (this.reconnectInterval) {
          clearInterval(this.reconnectInterval);
          this.reconnectInterval = null;
        }
        // Send START_CAPTURE command immediately upon connection to resume sniffer
        this.sendControlCommand("START_CAPTURE");
      };

      this.client.onerror = (error) => {
        console.error("WebSocket Error:", error);
        this.isConnected = false;
        // Schedule a reconnect attempt if not already scheduled
        if (!this.reconnectInterval) {
          this.reconnectInterval = setInterval(() => this.connect(), 5000); // Attempt every 5 seconds
        }
      };

      this.client.onclose = () => {
        console.log("WebSocket connection closed.");
        this.isConnected = false;
        this.isCapturing = false;
        this.showSnackbar("WebSocket Connection Closed.", "error");
        // Schedule a reconnect attempt if not already scheduled
        if (!this.reconnectInterval) {
          this.reconnectInterval = setInterval(() => this.connect(), 5000);
        }
      };

      this.client.onmessage = (event) => {
        let msgObj = null;
        try {
          msgObj = JSON.parse(event.data);
        } catch (e) {
          console.error(
            "Failed to parse WebSocket message as JSON:",
            event.data
          );
          return;
        }

        // Handle STATUS messages (control ACKs)
        if (msgObj.type === "STATUS") {
          if (msgObj.status === "CAPTURE_STARTED") {
            this.isCapturing = true;
            this.showSnackbar("Packet capture started.", "success");
          } else if (msgObj.status === "CAPTURE_STOPPED") {
            this.isCapturing = false;
            this.showSnackbar("Packet capture paused.", "warning");
          }
          console.log("Status update:", msgObj.status);
          return;
        }

        // Handle PACKET_DATA messages
        if (
          msgObj.type === "PACKET_DATA" &&
          msgObj.packet &&
          typeof msgObj.packet === "string"
        ) {
          const base64Packet = msgObj.packet;
          try {
            const binaryString = atob(base64Packet);
            const len = binaryString.length;

            if (len < 4) {
              console.warn(`Skipping tiny packet received (len: ${len})`);
              return;
            }

            // Store the base64 packet string
            this.rawPackets.push(base64Packet);

            // Update metrics
            this.packetsLastSecond++;
            this.totalDataSize += len;

            // Update log
            const rawPacket = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
              rawPacket[i] = binaryString.charCodeAt(i);
            }
            const preview = Array.from(rawPacket)
              .slice(0, 16)
              .map((byte) => byte.toString(16).padStart(2, "0"))
              .join(" ");

            this.lastPackets.unshift({
              timestamp: new Date().toLocaleTimeString(),
              length: len,
              preview: preview + "...",
            });

            if (this.lastPackets.length > 10) {
              this.lastPackets.pop();
            }
          } catch (error) {
            console.error("Error decoding base64 packet:", error);
          }
        }
      };
    },

    sendControlCommand(command) {
      if (this.client && this.client.readyState === WebSocket.OPEN) {
        const payload = JSON.stringify({ command, timestamp: Date.now() });
        this.client.send(payload);
        console.log(`Sent command: ${command}`);
      } else {
        this.showSnackbar(
          "Cannot send command: WebSocket not connected.",
          "error"
        );
      }
    },

    startCapture() {
      this.sendControlCommand("START_CAPTURE");
    },

    stopCapture() {
      this.sendControlCommand("STOP_CAPTURE");
    },

    clearPackets() {
      this.rawPackets = [];
      this.lastPackets = [];
      this.totalDataSize = 0;
      this.packetsPerSecond = 0;
      this.packetsLastSecond = 0;
      this.filename = null;
      this.downloadLink = null;
      this.showSnackbar("Packet buffer cleared.", "info");
    },

    stopCaptureAndDownload() {
      if (this.rawPackets.length === 0) {
        this.showSnackbar("No packets captured to generate PCAP.", "warning");
        return;
      }

      this.stopCapture();
      this.isGenerating = true;
      this.showSnackbar(
        "Packet capture stopped and initiating PCAP generation...",
        "info"
      );

      // CRITICAL: Generate a new session ID for this job
      this.sessionId = this.generateUniqueId();

      // Allow a brief moment for the STOP_CAPTURE command to take effect on the sniffer
      setTimeout(() => {
        this.generatePcap();
      }, 500);
    },

    async sendPacketsToFlask(chunk, chunkIndex, totalChunks, isFinalChunk) {
      const MAX_RETRIES = 3;
      let attempt = 0;

      // The chunk already contains Base64 strings, so we send it directly
      const payload = {
        session_id: this.sessionId,
        packets: chunk, // Chunk of Base64 strings
        is_final_chunk: isFinalChunk,
      };

      while (attempt < MAX_RETRIES) {
        attempt++;
        try {
          console.log(
            `Sending chunk ${
              chunkIndex + 1
            }/${totalChunks} (Attempt ${attempt})...`
          );

          const response = await fetch(`${this.apiUrl}/save-pcap`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });

          const data = await response.json();

          if (response.ok && data.success) {
            console.log(`Chunk ${chunkIndex + 1} processed successfully.`);
            return data;
          } else {
            const errorMessage =
              data.error || `Unknown error: ${response.status}`;
            console.error(`API error (attempt ${attempt}): ${errorMessage}`);
            throw new Error(errorMessage);
          }
        } catch (error) {
          console.error(error);
          if (attempt === MAX_RETRIES) {
            throw new Error(
              `Failed to process chunk ${chunkIndex + 1}: ${error.message}`
            );
          }
          // Exponential backoff
          await new Promise((resolve) =>
            setTimeout(resolve, 1000 * Math.pow(2, attempt))
          );
        }
      }
    },

    async generatePcap() {
      const packets = this.rawPackets; // Base64 strings
      const totalPackets = packets.length;
      console.log(`Generating PCAP from ${totalPackets} packets...`);

      const totalChunks = Math.ceil(totalPackets / this.chunkSize);
      let downloadData = null;

      try {
        for (let i = 0; i < totalChunks; i++) {
          const start = i * this.chunkSize;
          const end = start + this.chunkSize;
          // Slice the array of Base64 strings
          const chunk = packets.slice(start, end);
          const isFinalChunk = i === totalChunks - 1;

          const responseData = await this.sendPacketsToFlask(
            chunk,
            i,
            totalChunks,
            isFinalChunk
          );

          if (isFinalChunk) {
            downloadData = responseData;
          }
        }

        if (downloadData && downloadData.filename) {
          this.filename = downloadData.filename;
          this.downloadLink = `${this.apiUrl}/generated_pcaps/${this.filename}`;
          this.showSnackbar(`PCAP file generated: ${this.filename}`, "success");
        } else {
          this.showSnackbar(
            "PCAP generation completed, but no filename received.",
            "warning"
          );
        }
      } catch (error) {
        console.error("PCAP Generation Failed:", error);
        this.showSnackbar(`PCAP Generation Failed: ${error.message}`, "error");
      } finally {
        this.isGenerating = false;
        // User must clear the buffer manually
      }
    },
    startClustering() {
      this.$router.push({
        name: "clustering",
        query: { id: this.filename },
      });
    },
  },
};
</script>

<style scoped>
/* Basic styling for the futuristic theme */
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
</style>
