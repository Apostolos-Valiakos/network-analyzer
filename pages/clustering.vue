<template>
  <v-container class="page-container">
    <v-card class="rounded-xl pa-6 mb-6" style="border: 1px solid var(--border)">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-chart-scatter-plot</v-icon>
        Network Analysis
      </h2>
      <p class="text-subtitle-1 mb-2 text-fade">
        Reference name: <span class="primary--text font-weight-bold">{{ filename }}</span>
      </p>
      <p class="text-subtitle-1 mb-2 text-fade">
        API endpoint: <span class="primary--text font-weight-medium">{{ pcapUrlDisplay }}</span>
      </p>
      <div @click="downloadPcap" class="text-subtitle-1 my-3" style="cursor: pointer">
        <v-icon color="primary" small class="mr-1">mdi-download</v-icon>
        Click <u class="primary--text">here</u> to download the <b>.pcap</b> file
      </div>
      <p class="text-subtitle-1 text-fade" v-if="e1 === 1">
        Suggested clusters (graph modularity):
        <span class="primary--text font-weight-bold text-h6">{{ suggestedClusters }}</span>
      </p>
    </v-card>

    <v-stepper v-model="e1" class="mt-4 rounded-xl" style="border: 1px solid var(--border)">
      <v-stepper-header class="themed-stepper-header">
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
      apiBaseUrl: process.env.API_BASE_URL || "http://127.0.0.1:5555",
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

        const response = await this.$apiFetch(`${this.apiBaseUrl}/clustering`, {
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
      try {
        const res = await this.$apiFetch(url);
        if (!res.ok) throw new Error("Download failed");
        const blob = await res.blob();
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = objectUrl;
        link.download = this.filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(objectUrl);
      } catch (err) {
        this.error = err.message;
      }
    },

    async saveResults() {
      try {
        const payload = {
          filename: this.filename,
          results: this.clusters,
          type: this.fileType,
        };

        const response = await this.$apiFetch(`${this.apiBaseUrl}/save-results`, {
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
        const response = await this.$apiFetch(
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
        const response = await this.$apiFetch(`${this.apiBaseUrl}/run_pipeline`, {
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
      try {
        const res = await this.$apiFetch(url);
        if (!res.ok) throw new Error("Download failed");
        const blob = await res.blob();
        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = objectUrl;
        link.download = `${file}.${this.fileType}`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(objectUrl);
      } catch (err) {
        this.error = err.message;
      }
    },
  },
};
</script>

<style scoped>
.page-container {
  min-height: 100vh;
  padding: 24px;
}

.themed-stepper-header {
  background: var(--stepper-hdr-bg) !important;
  border-bottom: 1px solid var(--accent-border);
  border-radius: 20px 20px 0 0 !important;
}

.control-btn {
  border-radius: 16px !important;
  font-weight: 700;
  text-transform: none;
  letter-spacing: 0.5px;
}

.raw-data,
.message-content {
  background: var(--highlight-bg);
  padding: 12px;
  border-radius: 8px;
  border-left: 4px solid var(--metric-value);
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  font-size: 0.85rem;
  color: var(--text-secondary);
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
