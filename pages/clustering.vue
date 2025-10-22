<template>
  <v-container class="futuristic-light-container">
    <v-card class="elevation-8 rounded-xl pa-6 mb-8">
      <h2 class="text-h5 font-weight-bold mb-4">Network Analysis</h2>
      <p class="text-subtitle-1">
        For later reference you can retrieve the network data using the name:
        <b class="text-primary">{{ this.filename }}</b>
      </p>
      <p class="text-subtitle-1">
        Using our API like this:
        <b class="text-primary">
          https://127.0.0.1:5000/generated_pcaps/{{ this.filename }}
        </b>
      </p>
      <div @click="downloadPcap" class="text-h6 font-weight-bold my-4">
        Or just click
        <u class="text-blue-darken-2 cursor-pointer">here</u>
        to download the <b>.pcap</b> file
      </div>
      <p class="text-subtitle-1" v-if="e1 === 1">
        Using the elbow method the suggested number of clusters is:
        <b class="text-primary">{{ this.suggestedClusters }}</b>
      </p>
    </v-card>

    <v-stepper v-model="e1" class="mt-4 rounded-xl elevation-8">
      <v-stepper-header class="card-header">
        <v-stepper-step :complete="e1 > 1" step="1">Clustering</v-stepper-step>
        <v-divider></v-divider>
        <v-stepper-step :complete="e1 > 2" step="2">Profiling</v-stepper-step>
        <v-divider></v-divider>
        <v-stepper-step step="3">Results</v-stepper-step>
      </v-stepper-header>

      <v-stepper-items>
        <!-- STEP 1: CLUSTERING -->
        <v-stepper-content step="1">
          <v-card class="pa-6 mb-8 rounded-xl connection-card">
            <h3 class="text-h6 font-weight-bold mb-4 text-primary">
              <v-icon color="primary" class="mr-2">mdi-chart-cluster</v-icon>
              Network Clustering Overview
            </h3>

            <p class="text-subtitle-1 mb-2">
              Using the elbow method, the suggested number of clusters is:
              <b class="text-primary">{{ suggestedClusters }}</b
              >.
            </p>
            <p class="text-subtitle-2 text-medium-emphasis">
              Adjust the cluster count if needed and visualize the resulting
              network graph below.
            </p>

            <v-divider class="my-4"></v-divider>

            <!-- Cluster Selection -->
            <v-select
              class="futuristic-input mb-6"
              :items="noOfclustersList"
              label="Number of Clusters"
              v-model="noOfclusters"
              @change="fetchAnalysis()"
            ></v-select>

            <!-- Network Graph Section -->
            <v-card
              class="mb-12 d-flex align-center justify-center pa-4"
              height="600px"
              elevation="0"
            >
              <v-progress-circular
                color="primary"
                indeterminate
                v-if="loading"
              />
              <NetworkGraph
                v-if="graphData"
                :graphData="graphData"
                :key="networkGraphKey"
                :edgeLength="30"
              />
            </v-card>

            <!-- Important Cluster Info -->
            <v-alert
              type="info"
              variant="tonal"
              border="start"
              color="primary"
              class="mb-6"
            >
              The most important cluster is:
              <b class="text-primary">{{ mostImportantCluster }}</b
              >, as it contains the highest network activity.
            </v-alert>

            <!-- Cluster Hierarchy Table -->
            <v-card class="rounded-xl packets-card mb-8">
              <v-card-title class="card-header">
                <v-icon color="primary" class="mr-2">mdi-sitemap</v-icon>
                Cluster Hierarchy
              </v-card-title>
              <v-data-table
                :headers="headers"
                :items="clusterHierarchy"
                item-value="cluster"
                class="packet-table"
                density="compact"
              >
                <template v-slot:item.cluster="{ item }">
                  <b>{{ item.cluster }}</b>
                </template>
                <template v-slot:item.score="{ item }">
                  {{ item.score }}
                </template>
                <template v-slot:item.total_packets="{ item }">
                  {{ item.total_packets }}
                </template>
                <template v-slot:item.unique_ips="{ item }">
                  {{ item.unique_ips }}
                </template>
              </v-data-table>
            </v-card>

            <!-- Save Results -->
            <v-card class="pa-6 rounded-xl connection-card">
              <h4 class="text-subtitle-1 font-weight-bold mb-3 text-primary">
                <v-icon color="primary" class="mr-2">mdi-content-save</v-icon>
                Save Clustering Results
              </h4>
              <p class="text-caption font-italic mb-4">
                You can download the clustering results in <b>.csv</b> or
                <b>.json</b>
                format.
              </p>

              <v-select
                class="futuristic-input mb-4"
                :items="['json', 'csv']"
                label="Choose File Type"
                v-model="fileType"
              />

              <div class="d-flex flex-wrap ga-4">
                <v-btn
                  @click="saveResults()"
                  color="green"
                  class="white--text control-btn"
                >
                  <v-icon start>mdi-content-save</v-icon>
                  Save Results ({{ fileType.toUpperCase() }})
                </v-btn>
                <!-- <v-btn
                  color="primary"
                  @click="e1 = 2"
                  :disabled="loading"
                  class="control-btn"
                >
                  Continue
                  <v-icon end>mdi-arrow-right</v-icon>
                </v-btn> -->
              </div>
            </v-card>
          </v-card>
          <div class="d-flex ga-4">
            <v-btn
              color="primary"
              @click="e1 = 2"
              :disabled="loading"
              class="control-btn"
            >
              Continue
              <v-icon end>mdi-arrow-right</v-icon>
            </v-btn>
          </div>

          <!-- Elbow Chart -->
          <v-card class="pa-6 mt-8 rounded-xl connection-card">
            <h4 class="text-subtitle-1 font-weight-bold mb-4 text-primary">
              <v-icon color="deep-purple-accent-4" class="mr-2">
                mdi-chart-line
              </v-icon>
              Elbow Method Visualization
            </h4>
            <ElbowChart v-if="elbowData.length > 1" :elbowData="elbowData" />
          </v-card>
        </v-stepper-content>

        <!-- STEP 2: CNN PROFILING -->
        <v-stepper-content step="2">
          <v-card class="pa-6 mb-8 rounded-xl connection-card">
            <h3 class="text-h6 font-weight-bold mb-4 text-primary">
              <v-icon color="primary" class="mr-2">mdi-brain</v-icon>
              Rule Based Analysis
            </h3>

            <v-alert
              v-if="cnnError"
              type="error"
              class="mb-4"
              icon="mdi-alert-circle"
              variant="tonal"
            >
              Error during CNN analysis: {{ cnnError }}
            </v-alert>

            <div class="d-flex align-center mb-4">
              <v-btn
                color="primary"
                size="large"
                @click="startCnnAnalysis"
                :loading="cnnLoading"
                :disabled="cnnLoading"
                class="white--text control-btn"
              >
                <v-icon start>mdi-send-circle</v-icon>
                Start Rule Based Analysis
              </v-btn>

              <v-progress-linear
                v-if="cnnLoading"
                indeterminate
                color="deep-purple-accent-4"
                class="ml-4 rounded-lg"
                height="10"
              ></v-progress-linear>
            </div>

            <v-divider class="my-4"></v-divider>

            <!-- DISPLAY CNN RESULTS -->
            <div v-if="cnnResults">
              <h4 class="text-subtitle-1 font-weight-bold mb-2">
                <v-icon color="success" class="mr-1">mdi-chart-bar</v-icon>
                Analysis Results Overview
              </h4>

              <v-row>
                <v-col cols="12" sm="6" md="4">
                  <v-card class="pa-3" variant="outlined" elevation="0">
                    <div class="text-caption text-medium-emphasis">
                      Most Frequent Class
                    </div>
                    <div class="text-h5 font-weight-bold text-success">
                      {{ cnnResults.most_frequent_class }}
                    </div>
                  </v-card>
                </v-col>
                <v-col cols="12" sm="6" md="4">
                  <v-card class="pa-3" variant="outlined" elevation="0">
                    <div class="text-caption text-medium-emphasis">
                      Total Classified Items
                    </div>
                    <div class="text-h5 font-weight-bold text-info">
                      {{ cnnResults.total_classified }}
                    </div>
                  </v-card>
                </v-col>
                <v-col cols="12" sm="6" md="4">
                  <v-card class="pa-3" variant="outlined" elevation="0">
                    <div class="text-caption text-medium-emphasis">
                      Processing Time (s)
                    </div>
                    <div class="text-h5 font-weight-bold text-warning">
                      {{ cnnResults.processing_time.toFixed(2) }}
                    </div>
                  </v-card>
                </v-col>
              </v-row>

              <v-divider class="my-4"></v-divider>

              <h4 class="text-subtitle-1 font-weight-bold mb-2">
                <v-icon color="deep-purple-accent-4" class="mr-1"
                  >mdi-table</v-icon
                >
                Classification Summary
              </h4>

              <v-data-table
                :headers="cnnHeaders"
                :items="cnnResults.rule_based_classification_summary"
                item-value="class_name"
                class="packet-table elevation-2"
                density="compact"
              >
                <template v-slot:item.ips="{ item }">
                  <div v-if="item.ips && item.ips.length">
                    <ul>
                      <li v-for="ip in item.ips" :key="ip">{{ ip }}</li>
                    </ul>
                  </div>
                  <div v-else>—</div>
                </template>
              </v-data-table>

              <v-divider class="my-4"></v-divider>

              <!-- Dynamic Pie Chart for CNN Results -->
              <h4 class="text-subtitle-1 font-weight-bold mb-2">
                <v-icon color="deep-purple-accent-4" class="mr-1">
                  mdi-chart-pie
                </v-icon>
                Classification Summary Chart
              </h4>
              <PieChart
                v-if="
                  cnnResults &&
                  cnnResults.rule_based_classification_summary.length
                "
                :chartData="formattedCnnChartData"
                chartTitle="Rule Based Classification Summary"
              />
            </div>

            <div v-else-if="!cnnLoading" class="text-center pa-4">
              <v-icon size="48" color="grey-lighten-1"
                >mdi-monitor-dashboard</v-icon
              >
              <p class="text-subtitle-1 text-medium-emphasis mt-2">
                Click "Start Rule Based Analysis" to process data.
              </p>
            </div>
          </v-card>

          <div class="d-flex ga-4">
            <v-btn color="secondary" @click="e1 = 1" class="control-btn">
              <v-icon start>mdi-arrow-left</v-icon>
              Previous
            </v-btn>
            <v-btn
              color="primary"
              @click="e1 = 3"
              :disabled="!cnnResults"
              class="control-btn"
            >
              Continue
              <v-icon end>mdi-arrow-right</v-icon>
            </v-btn>
          </div>
        </v-stepper-content>

        <!-- STEP 3: RESULTS -->
        <v-stepper-content step="3">
          <v-card class="pa-6 mb-8 rounded-xl connection-card">
            <h3 class="text-h6 font-weight-bold mb-4 text-primary">
              <v-icon color="primary" class="mr-2">mdi-file-export</v-icon>
              Export & Final Results
            </h3>

            <p class="text-subtitle-1 mb-4">
              You can export the final <b>Roles</b> data or re-download the
              <b>.pcap</b> file for further analysis. Choose your preferred file
              format below.
            </p>

            <v-divider class="my-4"></v-divider>

            <!-- File Type Selector -->
            <v-select
              class="futuristic-input mb-6"
              :items="['json', 'csv']"
              label="Select Export File Type"
              v-model="fileType"
            ></v-select>

            <!-- Action Buttons -->
            <div class="d-flex flex-wrap ga-4">
              <v-btn
                color="green"
                class="white--text control-btn"
                size="large"
                @click="saveRoles"
              >
                <v-icon start>mdi-content-save</v-icon>
                Download Roles ({{ fileType.toUpperCase() }})
              </v-btn>

              <v-btn
                color="blue"
                class="white--text control-btn"
                size="large"
                @click="downloadPcap"
              >
                <v-icon start>mdi-download</v-icon>
                Download PCAP File
              </v-btn>
            </div>

            <v-divider class="my-6"></v-divider>

            <div class="text-center pa-4">
              <v-icon size="48" color="primary">mdi-check-decagram</v-icon>
              <p class="text-subtitle-1 text-medium-emphasis mt-2">
                All analysis completed successfully.
              </p>
              <p class="text-caption text-medium-emphasis">
                You can now save your data or return to previous steps for
                review.
              </p>
            </div>
          </v-card>

          <div class="d-flex ga-4">
            <v-btn color="secondary" @click="e1 = 2" class="control-btn">
              <v-icon start>mdi-arrow-left</v-icon>
              Previous
            </v-btn>
            <v-btn color="primary" @click="e1 = 1" class="control-btn">
              <v-icon start>mdi-restart</v-icon>
              Start Over
            </v-btn>
          </div>
        </v-stepper-content>
      </v-stepper-items>
    </v-stepper>
  </v-container>
</template>

<script>
import NetworkGraph from "../components/NetworkGraph.vue";
import PieChart from "../components/PieChart.vue";
import ElbowChart from "../components/elbowChart.vue";

export default {
  components: {
    NetworkGraph,
    ElbowChart,
    PieChart,
  },

  data() {
    return {
      filename: "",
      networkGraphKey: 0,
      e1: 1,
      graphData: null,
      error: null,
      loading: true,
      distanceThreshold: null,
      noOfclustersList: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
      noOfclusters: 4,
      fileType: "json",
      suggestedClusters: null,
      elbowData: [],
      mostImportantCluster: null,
      clusterHierarchy: [],
      cnnChartInstance: null,
      headers: [
        { text: "Cluster", value: "cluster" },
        { text: "Score", value: "score" },
        { text: "Total Packets", value: "total_packets" },
        { text: "Unique IPs", value: "unique_ips" },
      ],
      cnnResults: null,
      cnnLoading: false,
      cnnError: null,
      cnnHeaders: [
        { text: "Class Name", value: "class_name" },
        { text: "Count", value: "count" },
        { text: "Percentage (%)", value: "percentage" },
        { text: "IP Addresses", value: "ips" },
      ],
    };
  },

  async created() {
    this.filename = this.$route.query.id;
    await this.askForClusters();
    this.fetchAnalysis();
  },

  methods: {
    async fetchAnalysis() {
      this.loading = true;
      this.error = null;

      try {
        const params = new URLSearchParams({
          file: this.filename,
          clusters: this.noOfclusters || 4,
          anomaly_threshold: this.anomalyThreshold || 3,
        });

        const response = await fetch(
          `http://127.0.0.1:5000/clustering?${params.toString()}`
        );

        if (!response.ok) {
          const errText = await response.text();
          throw new Error(`API error: ${response.status} - ${errText}`);
        }

        const data = await response.json();
        this.clusters = data.clusters;
        this.graphData = data.graphData;
      } catch (err) {
        this.error = err.message;
      } finally {
        this.loading = false;
        this.networkGraphKey++;
      }
    },

    async downloadPcap() {
      const downloadUrl = `http://127.0.0.1:5000/generated_pcaps/${this.filename}`;
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.setAttribute("download", this.filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },

    async saveResults() {
      this.error = null;
      var file =
        this.filename.substring(0, this.filename.length - 5) +
        "_clusters." +
        this.fileType;
      const downloadUrl = `http://127.0.0.1:5000/save_results?file=${file}&type=${this.fileType}`;
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.setAttribute(
        "download",
        this.filename.replace(/\.[^/.]+$/, "") + "_clusters." + this.fileType
      );
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },

    async askForClusters() {
      this.error = null;
      try {
        const params = new URLSearchParams({
          file: this.filename,
        });
        const response = await fetch(
          `http://127.0.0.1:5000/suggested_clusters?${params.toString()}`
        );
        if (!response.ok) {
          const errText = await response.text();
          throw new Error(`API error: ${response.status} - ${errText}`);
        }
        const data = await response.json();
        this.mostImportantCluster = data.mostImportantCluster;
        this.suggestedClusters = data.elbow_point;
        this.noOfclusters = this.suggestedClusters;
        this.elbowData = data.wcss_data;
        this.clusterHierarchy = data.cluster_hierarchy;
      } catch (err) {
        this.error = err.message;
      } finally {
        this.loading = false;
        this.networkGraphKey++;
      }
    },

    async startCnnAnalysis() {
      this.cnnLoading = true;
      this.cnnError = null;
      this.cnnResults = null;

      const API_URL = "http://127.0.0.1:5000/run_pipeline";
      const payload = {
        pcap_file_path: this.filename,
        model_name: this.filename.replace(/\.[^/.]+$/, ""),
      };

      try {
        const response = await fetch(API_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || "Pipeline error");
        }

        const data = await response.json();
        this.cnnResults = data; // Save API response
      } catch (error) {
        this.cnnError = error.message;
      } finally {
        this.cnnLoading = false;
      }
    },
    async saveRoles() {
      this.error = null;
      var file = this.filename.substring(0, this.filename.length - 5);
      const downloadUrl = `http://127.0.0.1:5000/save_roles?file=${file}&type=${this.fileType}`;
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.setAttribute(
        "download",
        this.filename.replace(/\.[^/.]+$/, "") + this.fileType
      );
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },
  },
  computed: {
    formattedCnnChartData() {
      if (
        !this.cnnResults ||
        !this.cnnResults.rule_based_classification_summary
      )
        return [];
      return this.cnnResults.rule_based_classification_summary.map((item) => ({
        name: item.class_name,
        value: item.count,
      }));
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
  border-radius: 25px !important;
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
  white-space: pre-wrap;
  word-break: break-word;
  overflow-wrap: anywhere;
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  font-size: 0.85rem;
  color: #1e293b;
}
</style>
