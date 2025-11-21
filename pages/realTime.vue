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
        {{ isGenerating ? "Generating PCAP..." : "Generate PCAP" }}
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
            >Connect</v-btn
          >
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
          <div
            v-if="currentInterface"
            class="mb-4 text-caption text-medium-emphasis"
          >
            Current Server Interface: <strong>{{ currentInterface }}</strong>
          </div>
          <div v-else class="mb-4 text-caption text-warning">
            Interface not set. Get interfaces and select one.
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

      <v-col cols="12" md="6">
        <v-card class="pa-4 data-card" elevation="0">
          <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
            Network Graph
          </v-card-title>

          <v-card-text class="pa-4 text-center">
            <v-skeleton-loader
              v-if="isGraphLoading"
              type="image"
              class="mx-auto"
              max-width="400"
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
  components: {
    NetworkGraph,
  },
  data() {
    return {
      // Configuration
      wsUrl: "ws://127.0.0.1:5001", // Default value, now user-editable
      apiUrl: "http://127.0.0.1:5000",
      chunkSize: 1000,

      // Interface State
      availableInterfaces: [], // List of interface names
      selectedInterface: null, // User-selected interface name
      currentInterface: null, // Interface currently configured on the server

      // State
      client: null,
      isConnected: false,
      isCapturing: false,
      isGenerating: false,
      rawPackets: [],
      sessionId: null,

      // UI/Metrics
      snackbar: false,
      snackbarText: "",
      snackbarType: "info",
      packetsLastSecond: 0,
      packetsPerSecond: 0,
      lastPackets: [],
      totalDataSize: 0,
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
    /**
     * @returns {string} The total captured data size converted to megabytes (MB), fixed to 2 decimal places.
     */
    totalDataSizeMb() {
      return (this.totalDataSize / (1024 * 1024)).toFixed(2);
    },
  },
  mounted() {
    // this.connect();
  },
  beforeDestroy() {
    clearInterval(this.reconnectInterval);
    if (this.client) {
      this.client.close();
    }
  },
  methods: {
    /**
     * @async
     * Handles the entire workflow for network visualization:
     * 1. Pauses live capture (if active).
     * 2. Resets graph display and shows loading skeleton.
     * 3. Calls `generatePcap` to create the PCAP file on the server.
     * 4. Calls the Flask API to analyze the saved PCAP file and update `graphData`.
     * 5. Resumes live capture afterwards.
     * @returns {void}
     */
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
        // NOTE: generatePcap sets the `this.filename` which is used below.
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
    /**
     * Displays a notification snackbar to the user.
     * @param {string} text - The message to display.
     * @param {string} [type='info'] - The type/color of the snackbar.
     * @returns {void}
     */
    showSnackbar(text, type = "info") {
      this.snackbarText = text;
      this.snackbarType = type;
      this.snackbar = true;
    },

    /**
     * Generates a unique, readable session ID for file uploads.
     * @returns {string} A unique ID string.
     */
    generateUniqueId() {
      return (
        "pcap_" +
        Math.random().toString(36).substring(2, 9) +
        Date.now().toString(36)
      );
    },

    /**
     * Updates the displayed packets per second metric based on the count from the last second.
     * Resets the counter for the next interval.
     * @returns {void}
     */
    updateMetrics() {
      this.packetsPerSecond = this.packetsLastSecond;
      this.packetsLastSecond = 0;
    },

    // --- WebSocket Connection ---
    /**
     * Establishes or re-establishes the WebSocket connection.
     * Sets up event handlers for open, error, close, and message.
     * Manages automatic reconnection attempts.
     * @returns {void}
     */
    connect() {
      setInterval(this.updateMetrics, 1000);
      if (this.client && this.client.readyState === WebSocket.OPEN) {
        this.client.close();
      }

      console.log(`Attempting to connect to ${this.wsUrl}...`);
      this.client = new WebSocket(this.wsUrl);
      this.isConnected = false;
      this.showSnackbar(`Connecting to ${this.wsUrl}...`, "info");

      this.client.onopen = () => {
        this.isConnected = true;
        this.showSnackbar("Connected to WebSocket Publisher.", "success");
        console.log("WebSocket connection established.");
        // Stop any pending reconnect attempts
        if (this.reconnectInterval) {
          clearInterval(this.reconnectInterval);
          this.reconnectInterval = null;
        }
        // NEW: Request interfaces immediately after connecting
        this.getInterfaces();
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
          // NEW: Handle interface update from server
          if (msgObj.current_interface) {
            this.currentInterface = msgObj.current_interface;
            this.selectedInterface = msgObj.current_interface;
            // Show success message if the interface was just set
            if (
              msgObj.status &&
              msgObj.status.includes("Capture interface set")
            ) {
              this.showSnackbar(msgObj.status, "success");
            }
          }
          if (msgObj.type === "ERROR") {
            this.showSnackbar(`Server Error: ${msgObj.message}`, "error");
          }
          console.log("Status update:", msgObj.status);
          return;
        }

        // NEW: Handle INTERFACE_LIST messages
        if (msgObj.type === "INTERFACE_LIST" && msgObj.interfaces) {
          const names = Object.keys(msgObj.interfaces);
          this.availableInterfaces = names;
          // Set the current interface if provided, otherwise default to the first
          this.currentInterface = msgObj.current_interface || names[0];
          this.selectedInterface = this.currentInterface; // Select it in the dropdown
          this.showSnackbar(
            `Found ${names.length} network interfaces.`,
            "info"
          );
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

    /**
     * Sends the command to the server to list all available network interfaces.
     * The response is handled in client.onmessage (INTERFACE_LIST).
     * @returns {void}
     */
    getInterfaces() {
      this.sendControlCommand("GET_INTERFACES");
      this.showSnackbar("Requesting network interfaces...", "info");
    },

    /**
     * Sends the selected interface name to the server for configuration.
     * Requires capture to be stopped first.
     * @returns {void}
     */
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
        // Revert the dropdown selection to the current interface
        this.selectedInterface = this.currentInterface;
        return;
      }

      // Send the SET_INTERFACE command with the selected interface name
      if (this.client && this.client.readyState === WebSocket.OPEN) {
        const payload = JSON.stringify({
          command: "SET_INTERFACE",
          interface: this.selectedInterface,
        });
        this.client.send(payload);
        console.log(`Sent command: SET_INTERFACE to ${this.selectedInterface}`);
        this.showSnackbar(
          `Attempting to set interface to ${this.selectedInterface}...`,
          "warning"
        );
      }
    },

    /**
     * Sends a control command (e.g., START_CAPTURE, STOP_CAPTURE) to the WebSocket server.
     * @param {string} command - The command string to send.
     * @returns {void}
     */
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

    /**
     * Initiates the packet capture by sending the START_CAPTURE command.
     * @returns {void}
     */
    startCapture() {
      // Prevent starting if no interface is set
      if (!this.currentInterface) {
        this.showSnackbar(
          "Please select a network interface first.",
          "warning"
        );
        return;
      }
      this.sendControlCommand("START_CAPTURE");
    },

    /**
     * Pauses the packet capture by sending the STOP_CAPTURE command.
     * @returns {void}
     */
    stopCapture() {
      this.sendControlCommand("STOP_CAPTURE");
    },

    /**
     * Clears all captured packet data and resets associated metrics/UI state.
     * @returns {void}
     */
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

    /**
     * Stops the live capture and initiates the PCAP file generation process.
     * @returns {void}
     */
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

    /**
     * @async
     * Sends a chunk of Base64 encoded packets to the Flask API for PCAP assembly.
     * Implements retry logic for robustness.
     * @param {string[]} chunk - Array of Base64 packet strings.
     * @param {number} chunkIndex - The 0-based index of the current chunk.
     * @param {number} totalChunks - The total number of chunks expected.
     * @param {boolean} isFinalChunk - True if this is the last chunk.
     * @returns {Promise<object>} The JSON response data from the API.
     * @throws {Error} If the API call fails after all retry attempts.
     */
    async sendPacketsToFlask(chunk, chunkIndex, totalChunks, isFinalChunk) {
      const MAX_RETRIES = 3;
      let attempt = 0;

      const payload = {
        session_id: this.sessionId,
        packets: chunk,
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
          await new Promise((resolve) =>
            setTimeout(resolve, 1000 * Math.pow(2, attempt))
          );
        }
      }
    },

    /**
     * @async
     * Manages the chunked upload of all captured packets to the Flask API
     * for assembly into a PCAP file. Sets the download link upon success.
     * @returns {void}
     */
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
      }
    },
    /**
     * Navigates the user to the 'clustering' route, passing the generated PCAP filename as a query parameter.
     * @returns {void}
     */
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
