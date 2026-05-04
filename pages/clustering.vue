<template>
  <v-container class="futuristic-light-container">
    <v-card class="elevation-8 rounded-xl pa-6 mb-8">
      <h2 class="text-h5 font-weight-bold mb-4">Network Analysis</h2>
      <p class="text-subtitle-1">
        For later reference you can retrieve the network data using the name:
        <b class="text-primary">{{ filename }}</b>
      </p>
      <p class="text-subtitle-1">
        Using our API like this:
        <b class="text-primary">
          {{ pcapUrlDisplay }}
        </b>
      </p>
      <div @click="downloadPcap" class="text-h6 font-weight-bold my-4">
        Or just click
        <u class="text-blue-darken-2 cursor-pointer">here</u>
        to download the <b>.pcap</b> file
      </div>
      <p class="text-subtitle-1" v-if="e1 === 1">
        Using <b>graph modularity</b>, the suggested number of clusters is:
        <b class="text-primary">{{ suggestedClusters }}</b>
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
        <v-stepper-content step="1">
          <StepClustering
            v-bind="clusteringProps"
            @next="e1 = 2"
            @update:noOfclusters="
              (v) => {
                noOfclusters = v;
                fetchAnalysis();
              }
            "
            @update:selectedCluster="(v) => (selectedCluster = v)"
            @update:fileType="(v) => (fileType = v)"
            @save-results="
              ({ fileType: ft }) => {
                fileType = ft;
                saveResults();
              }
            "
          />
        </v-stepper-content>

        <v-stepper-content step="2">
          <StepProfiling
            v-bind="profilingProps"
            @prev="e1 = 1"
            @next="e1 = 3"
            @start-analysis="startAnalysisWithIps"
          />
        </v-stepper-content>

        <v-stepper-content step="3">
          <StepResults
            v-bind="resultsProps"
            @prev="e1 = 2"
            @restart="e1 = 1"
            @download-pcap="downloadPcap"
            @save-roles="
              (ft) => {
                fileType = ft;
                saveRoles();
              }
            "
            @update:fileType="(v) => (fileType = v)"
          />
        </v-stepper-content>
      </v-stepper-items>
    </v-stepper>
  </v-container>
</template>

<script>
import StepClustering from "@/components/stepper/StepClustering.vue";
import StepProfiling from "@/components/stepper/StepProfiling.vue";
import StepResults from "@/components/stepper/StepResults.vue";

export default {
  components: {
    StepClustering,
    StepProfiling,
    StepResults,
  },

  data() {
    return {
      e1: 1,
      filename: "",
      networkGraphKey: 0,
      loading: true,
      graphData: null,
      allIps: null,
      selectedCluster: [],
      selectedIps: [],
      noOfclusters: 4,
      noOfclustersList: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
      fileType: "json",
      apiBaseUrl: process.env.VUE_APP_API_BASE_URL || "http://127.0.0.1:5555",
      suggestedClusters: null,
      modularityData: [],
      bestModularity: null,
      mostImportantCluster: null,
      clusterHierarchy: [],
      cnnResults: null,
      cnnLoading: false,
      cnnError: null,
      clusters: [],
      headers: [
        { text: "Cluster", value: "cluster" },
        { text: "Score", value: "score" },
        { text: "Traffic Score", value: "total_packets" },
        { text: "Unique IPs", value: "unique_ips" },
      ],
      cnnHeaders: [
        {
          text: "Role / Class Name",
          value: "class_name",
          align: "start",
          width: "25%",
        },
        {
          text: "Count",
          value: "count",
          sortable: true,
          width: "15%",
        },
        {
          text: "Distribution", // NEW FIELD
          value: "percentage",
          align: "center",
          width: "20%",
        },
        {
          text: "Assigned IP Addresses",
          value: "ips",
          sortable: false,
        },
      ],
    };
  },
  computed: {
    pcapUrlDisplay() {
      if (!this.filename) {
        return `${this.apiBaseUrl}/generated_pcaps/`;
      }
      return `${this.apiBaseUrl}/generated_pcaps/${this.filename}`;
    },
    clusteringProps() {
      return {
        filename: this.filename,
        loading: this.loading,
        graphData: this.graphData,
        networkGraphKey: this.networkGraphKey,
        noOfclusters: this.noOfclusters,
        noOfclustersList: this.noOfclustersList,
        suggestedClusters: this.suggestedClusters,
        mostImportantCluster: this.mostImportantCluster,
        allIps: this.allIps,
        selectedCluster: this.selectedCluster,
        modularityData: this.modularityData,
        bestModularity: this.bestModularity,
        clusterHierarchy: this.clusterHierarchy,
        headers: this.headers,
        fileType: this.fileType,
      };
    },

    profilingProps() {
      return {
        filename: this.filename,
        cnnLoading: this.cnnLoading,
        cnnResults: this.cnnResults,
        cnnError: this.cnnError,
        cnnHeaders: this.cnnHeaders,
        formattedCnnChartData: this.formattedCnnChartData,
        selectedIps: this.selectedIps,
      };
    },

    resultsProps() {
      return {
        filename: this.filename,
        fileType: this.fileType,
      };
    },

    formattedCnnChartData() {
      if (!this.cnnResults?.rule_based_classification_summary) return [];
      return this.cnnResults.rule_based_classification_summary.map((item) => ({
        name: item.class_name,
        value: item.count,
      }));
    },
  },

  watch: {
    selectedCluster(newVal) {
      this.selectedIps = [];
      if (!newVal?.length || !this.graphData?.nodes) return;
      const clusterIdx = newVal[0];
      this.graphData.nodes.forEach((node) => {
        if (node.category === clusterIdx) {
          this.selectedIps.push(node.name);
        }
      });
    },
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
        const payload = {
          file: this.filename,
          clusters: this.noOfclusters || 4,
          anomaly_threshold: 3,
        };

        const response = await fetch(`${this.apiBaseUrl}/clustering`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const err = await response.text();
          throw new Error(`API error: ${response.status} – ${err}`);
        }

        const data = await response.json();
        this.graphData = data.graphData;
        this.clusters = data.clusters;

        if (this.graphData?.nodes) {
          this.allIps = [
            ...new Set(this.graphData.nodes.map((n) => n.category)),
          ];
        }
      } catch (err) {
        this.error = err.message;
      } finally {
        this.loading = false;
        this.networkGraphKey++;
      }
    },

    async downloadPcap() {
      const url = `${this.apiBaseUrl}/generated_pcaps/${this.filename}`;
      const link = document.createElement("a");
      link.href = url;
      link.download = this.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    },

    async saveResults() {
      try {
        const payload = {
          filename: this.filename,
          results: this.clusters,
          type: this.fileType,
        };

        const response = await fetch(`${this.apiBaseUrl}/save-results`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const err = await response.json();
          throw new Error(err.error || `Save failed (${response.status})`);
        }

        const data = await response.json();
        if (data.download_url) {
          const link = document.createElement("a");
          link.href = `${this.apiBaseUrl}${data.download_url}`;
          link.download = data.saved_file;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
        }
      } catch (err) {
        this.error = err.message;
        console.error(err);
      }
    },

    async askForClusters() {
      try {
        const params = new URLSearchParams({ file: this.filename });
        const response = await fetch(
          `${this.apiBaseUrl}/suggested_clusters?${params}`
        );

        if (!response.ok) {
          const errText = await response.text();
          throw new Error(`API error: ${response.status} - ${errText}`);
        }

        const data = await response.json();

        this.suggestedClusters = data.best_k;
        this.noOfclusters = data.best_k;

        this.bestModularity = data.best_modularity;
        this.modularityData = data.modularity_scores;

        this.mostImportantCluster = data.mostImportantCluster;
        this.clusterHierarchy = data.cluster_hierarchy;
      } catch (err) {
        this.error = err.message;
      }
    },

    async startAnalysisWithIps({ selectedIps } = {}) {
      this.cnnLoading = true;
      this.cnnError = null;
      this.cnnResults = null;

      if (selectedIps) this.selectedIps = selectedIps;

      const payload = {
        pcap_file_path: this.filename,
        model_name: this.filename.replace(/\.[^/.]+$/, ""),
        selected_ips: this.selectedIps.length ? this.selectedIps : undefined,
      };

      try {
        const response = await fetch(`${this.apiBaseUrl}/run_pipeline`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || "Pipeline error");
        }

        const data = await response.json();
        this.cnnResults = data;
      } catch (error) {
        this.cnnError = error.message;
      } finally {
        this.cnnLoading = false;
      }
    },

    async saveRoles() {
      const file = this.filename.substring(0, this.filename.lastIndexOf("."));
      const url = `${this.apiBaseUrl}/save_roles?file=${file}&type=${this.fileType}`;
      const link = document.createElement("a");
      link.href = url;
      link.download = `${file}.${this.fileType}`;
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
  border: 2px solid rgba(59, 130, 246);
  border-radius: 25px !important;
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

.timestamp-cell,
.length-cell {
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  font-size: 0.85rem;
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

.raw-data,
.message-content {
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
</style>
