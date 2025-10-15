<!-- :TODO Στις γραμμές που εννώνουν τους κόμβους, να φαίνονται τα πακέτα που ανταλάσουν οι κόμβοι, ή στο hover -->
<template>
  <div class="futuristic-light-container">
    <!-- {{ this.mqttMessages.length }} -->
    <!-- Status Header -->
    <v-card class="status-card mb-6" elevation="0">
      <v-card-text class="pa-4">
        <div class="d-flex align-center justify-space-between">
          <div class="d-flex align-center">
            <div class="status-indicator" :class="statusClass"></div>
            <div class="ml-4">
              <h2 class="status-title">MQTT Connection</h2>
              <p class="status-text mb-0">{{ connectionStatus }}</p>
            </div>
          </div>
          <v-chip
            :color="isConnected ? 'success' : 'error'"
            variant="flat"
            class="status-chip"
          >
            {{ isConnected ? "ONLINE" : "OFFLINE" }}
          </v-chip>
        </div>
      </v-card-text>
    </v-card>

    <!-- Connection Form -->
    <v-card class="connection-card mb-6" elevation="0">
      <v-card-title class="card-header">
        <v-icon class="mr-2" color="primary">mdi-connection</v-icon>
        Connection Settings
      </v-card-title>
      <v-card-text class="pa-6">
        <v-container fluid>
          <v-row>
            <v-col cols="12" sm="6">
              <v-text-field
                label="Host IP address"
                placeholder="e.g. 127.0.0.1"
                variant="outlined"
                clearable
                :rules="[required]"
                v-model="hostAddress"
                prepend-inner-icon="mdi-server-network"
                class="futuristic-input"
                color="primary"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                label="Username"
                variant="outlined"
                clearable
                type="text"
                v-model="username"
                :rules="[required]"
                prepend-inner-icon="mdi-account"
                class="futuristic-input"
                color="primary"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                label="Password"
                variant="outlined"
                clearable
                type="password"
                v-model="password"
                :rules="[required]"
                prepend-inner-icon="mdi-lock"
                class="futuristic-input"
                color="primary"
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-text-field
                label="Topic"
                variant="outlined"
                clearable
                type="text"
                v-model="topic"
                :rules="[required]"
                prepend-inner-icon="mdi-message-text"
                class="futuristic-input"
                color="primary"
              />
            </v-col>
          </v-row>
        </v-container>

        <!-- Error Display -->
        <v-alert
          v-if="error"
          type="error"
          variant="tonal"
          class="mt-4 error-alert"
          icon="mdi-alert-circle"
        >
          {{ error }}
        </v-alert>

        <!-- Server Response / Messages -->
        <v-alert
          v-if="flaskMessage"
          :type="flaskMessageType"
          variant="tonal"
          class="mt-4"
          :icon="
            flaskMessageType === 'success'
              ? 'mdi-check-circle'
              : 'mdi-alert-circle'
          "
        >
          {{ flaskMessage }}
        </v-alert>

        <!-- Control Buttons -->
        <div class="controls-section mt-6">
          <v-btn
            @click="connect"
            :disabled="isConnected"
            color="primary"
            size="large"
            variant="flat"
            class="control-btn mr-3"
            prepend-icon="mdi-power-plug"
          >
            Connect
          </v-btn>
          <v-btn
            @click="disconnect"
            :disabled="!isConnected"
            color="error"
            size="large"
            variant="flat"
            class="control-btn mr-3"
            prepend-icon="mdi-power-plug-off"
          >
            Disconnect
          </v-btn>
          <v-btn
            @click="testPublish"
            :disabled="!isConnected"
            color="success"
            size="large"
            variant="flat"
            class="control-btn"
            prepend-icon="mdi-send"
          >
            Test Publish
          </v-btn>

          <v-btn
            @click="downloadPcap"
            :disabled="!rawPackets.length || isSendingPcap"
            color="green"
            size="large"
            variant="flat"
            class="control-btn"
            prepend-icon="mdi-download"
          >
            {{ isSendingPcap ? "Generating..." : `Download PCAP` }}
          </v-btn>

          <v-btn
            @click="clearCollectedPackets"
            :disabled="!rawPackets.length || isSendingPcap"
            color="orange"
            size="large"
            variant="flat"
            class="control-btn"
            prepend-icon="mdi-eraser"
          >
            Clear Collected Packets
          </v-btn>
          <v-btn
            @click="visualizeNetwork"
            :disabled="!rawPackets.length || isSendingPcap"
            color="red"
            size="large"
            variant="flat"
            class="control-btn"
          >
            Vizualize Network
          </v-btn>
        </div>
      </v-card-text>
    </v-card>
    <v-btn
      :disabled="!rawPackets.length || isSendingPcap"
      @click="startClustering()"
      color="red"
      size="large"
      variant="flat"
      class="control-btn mb-4"
    >
      Start Analysis
    </v-btn>
    <v-row>
      <v-col>
        <v-card class="connection-card mb-6" elevation="2">
          <v-card-title class="card-header">
            <v-icon class="mr-2" color="primary">mdi-graph</v-icon>
            Network Graph
          </v-card-title>
          <v-card-text class="pa-6">
            <v-container fluid class="text-center">
              <v-progress-circular
                color="primary"
                indeterminate
                v-if="!graphData"
              ></v-progress-circular>
              <NetworkGraph
                v-if="graphData"
                :graphData="graphData"
                :key="graphKey"
              />
            </v-container>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col>
        <!-- Search & Filter -->
        <v-card class="mb-4 px-4 py-2 connection-card" elevation="0">
          <v-row>
            <v-col cols="12" sm="6">
              <v-text-field
                v-model="searchText"
                label="Search Messages"
                prepend-inner-icon="mdi-magnify"
                variant="outlined"
                clearable
                dense
                hide-details
              />
            </v-col>
            <v-col cols="12" sm="6">
              <v-select
                v-model="selectedTopic"
                :items="uniqueTopics"
                label="Filter by Topic"
                prepend-inner-icon="mdi-filter"
                variant="outlined"
                clearable
                dense
                hide-details
              />
            </v-col>
          </v-row>
        </v-card>
        <!-- Messages Section -->
        <v-card elevation="0">
          <v-card-title class="card-header">
            <v-icon class="mr-2" color="primary">mdi-message-processing</v-icon>
            Message Stream
            <v-spacer></v-spacer>
            <v-chip
              v-if="filteredMessages.length"
              color="info"
              variant="flat"
              size="small"
            >
              {{ filteredMessages.length }} messages
            </v-chip>
          </v-card-title>
          <v-card-text class="pa-0">
            <div v-if="filteredMessages.length" class="messages-container">
              <v-virtual-scroll
                :items="filteredMessages"
                height="400"
                item-height="120"
              >
                <template v-slot:default="{ item, index }">
                  <div class="message-item" :key="index">
                    <v-card class="message-card ma-3" variant="outlined">
                      <v-card-text class="pa-4">
                        <div
                          class="d-flex justify-space-between align-center mb-2"
                        >
                          <v-chip
                            color="primary"
                            variant="flat"
                            size="small"
                            class="topic-chip"
                          >
                            {{ item.topic }}
                          </v-chip>
                          <span class="timestamp">{{ item.time }}</span>
                        </div>
                        <pre class="message-content">{{ item.text }}</pre>
                      </v-card-text>
                    </v-card>
                  </div>
                </template>
              </v-virtual-scroll>
            </div>
            <div v-else class="waiting-state">
              <div class="text-center pa-8">
                <v-icon size="64" color="primary" class="mb-4"
                  >mdi-satellite-uplink</v-icon
                >
                <h3 class="waiting-title mb-2">Waiting for Messages</h3>
                <p class="waiting-subtitle">
                  Connect to start receiving MQTT messages
                </p>
              </div>
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>
    <!-- <v-card
      class="connection-card mb-6"
      elevation="2"
      v-if="shouldShowGraphCard"
    >
      <v-card-title class="card-header">
        <v-icon class="mr-2" color="primary">mdi-graph</v-icon>
        Network Graph
      </v-card-title>
      <v-card-text class="pa-6">
        <v-container fluid class="text-center">
          <v-progress-circular
            color="primary"
            indeterminate
            v-if="!graphData"
          ></v-progress-circular>
          <NetworkGraph
            v-if="graphData"
            :graphData="graphData"
            :key="graphKey"
          />
        </v-container>
      </v-card-text>
    </v-card> -->

    <!-- Search & Filter -->
    <!-- <v-card class="mb-4 px-4 py-2 connection-card" elevation="0">
      <v-row>
        <v-col cols="12" sm="6">
          <v-text-field
            v-model="searchText"
            label="Search Messages"
            prepend-inner-icon="mdi-magnify"
            variant="outlined"
            clearable
            dense
            hide-details
          />
        </v-col>
        <v-col cols="12" sm="6">
          <v-select
            v-model="selectedTopic"
            :items="uniqueTopics"
            label="Filter by Topic"
            prepend-inner-icon="mdi-filter"
            variant="outlined"
            clearable
            dense
            hide-details
          />
        </v-col>
      </v-row>
    </v-card> -->
    <!-- Messages Section -->
    <!-- <v-card class="messages-card" elevation="0">
      <v-card-title class="card-header">
        <v-icon class="mr-2" color="primary">mdi-message-processing</v-icon>
        Message Stream
        <v-spacer></v-spacer>
        <v-chip
          v-if="filteredMessages.length"
          color="info"
          variant="flat"
          size="small"
        >
          {{ filteredMessages.length }} messages
        </v-chip>
      </v-card-title>
      <v-card-text class="pa-0">
        <div v-if="filteredMessages.length" class="messages-container">
          <v-virtual-scroll
            :items="filteredMessages"
            height="400"
            item-height="120"
          >
            <template v-slot:default="{ item, index }">
              <div class="message-item" :key="index">
                <v-card class="message-card ma-3" variant="outlined">
                  <v-card-text class="pa-4">
                    <div class="d-flex justify-space-between align-center mb-2">
                      <v-chip
                        color="primary"
                        variant="flat"
                        size="small"
                        class="topic-chip"
                      >
                        {{ item.topic }}
                      </v-chip>
                      <span class="timestamp">{{ item.time }}</span>
                    </div>
                    <pre class="message-content">{{ item.text }}</pre>
                  </v-card-text>
                </v-card>
              </div>
            </template>
          </v-virtual-scroll>
        </div>
        <div v-else class="waiting-state">
          <div class="text-center pa-8">
            <v-icon size="64" color="primary" class="mb-4"
              >mdi-satellite-uplink</v-icon
            >
            <h3 class="waiting-title mb-2">Waiting for Messages</h3>
            <p class="waiting-subtitle">
              Connect to start receiving MQTT messages
            </p>
          </div>
        </div>
      </v-card-text>
    </v-card> -->
  </div>
</template>

<script>
import mqtt from "mqtt";

export default {
  data() {
    return {
      shouldShowGraphCard: false,
      client: null,
      username: "avaliakos",
      password: "h3jj0w2u",
      hostAddress: "127.0.0.1:9001",
      // topic: "test/topic",
      topic: "network/data",
      isConnected: false,
      connectionStatus: "Disconnected",
      mqttMessages: [],
      error: null,
      searchText: "",
      selectedTopic: null,
      required(v) {
        return !!v || "Field is required";
      },
      rawPackets: [],
      isSendingPcap: false,
      flaskMessage: "",
      flaskMessageType: "",
      filename: "",
      FLASK_SERVER_BASE_URL: "http://localhost:5000",
      graphData: null,
      graphKey: 0,
    };
  },
  computed: {
    filteredMessages() {
      return this.mqttMessages.filter((msg) => {
        const matchesSearch = this.searchText
          ? msg.text.toLowerCase().includes(this.searchText.toLowerCase()) ||
            msg.topic.toLowerCase().includes(this.searchText.toLowerCase())
          : true;
        const matchesTopic = this.selectedTopic
          ? msg.topic === this.selectedTopic
          : true;
        return matchesSearch && matchesTopic;
      });
    },
    uniqueTopics() {
      const topics = this.mqttMessages.map((msg) => msg.topic);
      return [...new Set(topics)];
    },
    statusClass() {
      return this.isConnected ? "online" : "offline";
    },
  },
  methods: {
    async downloadPcap() {
      await this.generatePcap();
      const downloadUrl = `${this.FLASK_SERVER_BASE_URL}/generated_pcaps/${this.filename}`;
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.setAttribute("download", this.filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },
    connect() {
      const [host, port] = this.hostAddress.split(":");
      const mqttBrokerUrl = `ws://${host}:${port}`;

      this.client = mqtt.connect(mqttBrokerUrl, {
        username: this.username,
        password: this.password,
      });

      this.client.on("connect", () => {
        this.isConnected = true;
        this.connectionStatus = "Connected";
        this.error = null;
        this.flaskMessage = ""; // Clear any previous Flask messages
        console.log(`Connected to MQTT Broker: ${mqttBrokerUrl}`);

        this.client.subscribe(this.topic, (err) => {
          if (!err) {
            console.log(`Subscribed to topic: ${this.topic}`);
          } else {
            console.error(`MQTT Subscription error: ${err}`);
            this.error = `Subscription error: ${err.message}`;
          }
        });
      });

      this.client.on("error", (err) => {
        this.isConnected = false;
        this.connectionStatus = "Disconnected";
        this.error = "Connection error: " + err.message;
        console.error("MQTT Connection Error:", err);
      });

      // this.client.on("message", (topic, message) => {
      //   this.rawPackets.push(...message);
      //   this.mqttMessages.unshift({
      //     topic: topic.toString(),
      //     text: message.toString(),
      //     time: new Date().toLocaleTimeString(),
      //   });
      // });

      this.client.on("message", (topic, message) => {
        const packetSize = message.length;
        const previewHex = Array.from(message.slice(0, 8))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join(" ");

        this.rawPackets.push(...message);

        this.mqttMessages.unshift({
          topic: topic.toString(),
          text: `Size: ${packetSize} bytes | Preview: ${previewHex}...`,
          time: new Date().toLocaleTimeString(),
        });
      });

      this.client.on("close", () => {
        this.isConnected = false;
        this.connectionStatus = "Disconnected";
        console.log("MQTT connection closed.");
      });

      this.client.on("reconnect", () => {
        this.connectionStatus = "Reconnecting...";
        console.log("MQTT reconnecting...");
      });
    },
    disconnect() {
      if (this.client) {
        this.client.end();
        this.client = null;
        this.isConnected = false;
        this.connectionStatus = "Disconnected";
        this.error = null;
        console.log("MQTT client disconnected.");
      }
    },
    testPublish() {
      if (this.client && this.topic) {
        const testMessage = `Test message from Vue app at ${new Date().toLocaleTimeString()}`;
        this.client.publish(
          this.topic,
          testMessage,
          { qos: 0 }, // QoS 0 for test messages
          (err) => {
            if (err) {
              console.error("Failed to publish test message:", err);
              this.error = "Failed to publish test message: " + err.message;
            } else {
              console.log("Test message published.");
            }
          }
        );
      } else {
        this.error = "Not connected or topic not set to publish test message.";
      }
    },
    async generatePcap() {
      if (this.rawPackets.length === 0) {
        this.status = "No packets collected to save.";
        return;
      }

      this.isSendingPcap = true;
      this.status = "Sending data to server...";

      try {
        // 1. Create a Uint8Array from the collected binary data
        const pcapData = new Uint8Array(this.rawPackets);

        // 2. Use a POST request with the correct URL and content type
        const response = await fetch("http://127.0.0.1:5000/save-pcap", {
          method: "POST",
          headers: {
            "Content-Type": "application/octet-stream",
          },
          body: pcapData, // Send the raw binary data directly
        });

        // 3. Handle the server's response
        const data = await response.json();

        if (response.ok) {
          this.status = `PCAP file saved successfully on server: ${data.filename}`;
          this.filename = data.filename;
          this.hasData = false;
        } else {
          this.status = `Error saving PCAP: ${data.error || "Unknown error"}`;
          console.error("Server error:", data.error || "Unknown error");
        }
      } catch (err) {
        this.status = `Network or server error: ${err.message}. Ensure Flask server is running and accessible.`;
        console.error("Error in PCAP saving:", err);
      } finally {
        this.isSendingPcap = false;
      }
    },
    async visualizeNetwork() {
      this.shouldShowGraphCard = true;
      this.graphData = null;
      this.graphKey++;
      await this.generatePcap();
      this.status = "Sending analysis request to server...";

      try {
        const response = await fetch(
          `${this.FLASK_SERVER_BASE_URL}/analyze-saved-pcap/${this.filename}`
        );

        const data = await response.json();

        if (response.ok) {
          this.status = `Analysis for ${this.filename} successful.`;
          // console.log("Analysis Result:", data.analysis);
          this.graphData = data.analysis.graph;
          this.graphKey++;
        } else {
          this.status = `Analysis failed: ${data.error}`;
          console.error("Analysis error:", data.error);
        }
      } catch (err) {
        this.status = `Network error during analysis: ${err.message}`;
        // console.error("Analysis network error:", err);
      }
    },
    clearCollectedPackets() {
      this.rawPackets = [];
      this.mqttMessages = [];
      this.flaskMessage =
        "All collected packets and displayed messages cleared.";
      this.flaskMessageType = "info";
      console.log("Client-side packet buffer and display cleared.");
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
.futuristic-light-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 50%, #cbd5e1 100%);
  padding: 24px;
}

.status-card {
  background: linear-gradient(135deg, #3b82f6 0%, #1d4ed8 100%) !important;
  border: 2px solid rgba(59, 130, 246, 0.2);
  border-radius: 20px !important;
  box-shadow: 0 10px 40px rgba(59, 130, 246, 0.15);
}

.status-indicator {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  position: relative;
  animation: pulse 2s infinite;
}

.status-indicator.status-connected {
  background: #10b981;
  box-shadow: 0 0 20px rgba(16, 185, 129, 0.6);
}

.status-indicator.status-disconnected {
  background: #ef4444;
  box-shadow: 0 0 20px rgba(239, 68, 68, 0.6);
}

@keyframes pulse {
  0% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.2);
    opacity: 0.7;
  }
  100% {
    transform: scale(1);
    opacity: 1;
  }
}

.status-title {
  color: white;
  font-weight: 700;
  font-size: 1.5rem;
  margin: 0;
}

.status-text {
  color: rgba(255, 255, 255, 0.9);
  font-size: 0.9rem;
}

.status-chip {
  font-weight: 700;
  letter-spacing: 1px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.connection-card,
.messages-card,
.filter-card,
.packets-card {
  background: rgba(255, 255, 255, 0.9) !important;
  border: 2px solid rgba(59, 130, 246, 0.1);
  border-radius: 20px !important;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.05);
  backdrop-filter: blur(10px);
}

.card-header {
  background: linear-gradient(
    135deg,
    rgba(59, 130, 246, 0.3) 0%,
    rgba(147, 197, 253, 0.05) 100%
  );
  color: #1e40af !important;
  font-weight: 700;
  border-bottom: 2px solid rgba(59, 130, 246, 0.1);
  border-radius: 20px 20px 0 0 !important;
}

.futuristic-input :deep(.v-field) {
  background: rgba(255, 255, 255, 0.8) !important;
  border: 2px solid rgba(59, 130, 246, 0.2);
  border-radius: 16px;
  transition: all 0.3s ease;
}

.futuristic-input :deep(.v-field--focused) {
  border-color: #3b82f6;
  box-shadow: 0 0 25px rgba(59, 130, 246, 0.2);
  background: rgba(255, 255, 255, 1) !important;
}

.error-alert {
  border-left: 4px solid #ef4444;
  background: rgba(239, 68, 68, 0.05) !important;
  border-radius: 12px;
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
  transition: all 0.3s ease;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
}

.control-btn:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
}

.packets-container {
  background: rgba(255, 255, 255, 0.5);
  border-radius: 0 0 20px 20px;
}

.packet-table :deep(.v-data-table__wrapper) {
  border-radius: 0 0 20px 20px;
}

.timestamp-cell {
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  font-size: 0.85rem;
  color: #64748b;
}

.length-cell {
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  font-size: 0.85rem;
  color: #059669;
}

.waiting-state {
  background: rgba(248, 250, 252, 0.8);
  color: #64748b;
  border-radius: 0 0 20px 20px;
}

.waiting-title {
  color: #1e40af;
  font-weight: 700;
}

.waiting-subtitle {
  color: #64748b;
  font-weight: 500;
}

.raw-data {
  background: #f8fafc;
  padding: 12px;
  border-radius: 8px;
  border-left: 4px solid #3b82f6;
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  font-size: 0.85rem;
  color: #1e293b;
  white-space: pre-wrap;
  word-break: break-all;
}
.message-content {
  white-space: pre-wrap; /* Preserve formatting but allow wrapping */
  word-break: break-word; /* Break long words if needed */
  overflow-wrap: anywhere; /* Ensure even long strings break */
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  font-size: 0.85rem;
  color: #1e293b;
}
</style>
