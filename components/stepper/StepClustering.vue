<template>
  <div>
    <!-- ──────── CLUSTERING CARD ──────── -->
    <v-card class="pa-6 mb-8 rounded-xl connection-card">
      <h3 class="text-h6 font-weight-bold mb-4 text-primary">
        <v-icon color="primary" class="mr-2">mdi-chart-cluster</v-icon>
        Network Clustering Overview
      </h3>

      <p class="text-subtitle-1 mb-2">
        Using the Graph Modularity Method, the suggested number of clusters is:
        <b class="text-primary">{{ suggestedClusters }}</b
        >.
      </p>

      <v-divider class="my-4"></v-divider>

      <!-- Cluster selector -->
      <v-select
        class="futuristic-input mb-6"
        :items="noOfclustersList"
        label="Number of Clusters"
        v-model="localClusters"
        @change="onClustersChange"
      ></v-select>

      <!-- Graph -->
      <v-card
        class="mb-12 d-flex align-center justify-center pa-4"
        height="600px"
        elevation="0"
      >
        <v-progress-circular color="primary" indeterminate v-if="loading" />
        <NetworkGraph
          v-else-if="graphData"
          :graphData="graphData"
          :key="networkGraphKey"
          :edgeLength="30"
        />
      </v-card>

      <!-- Most important cluster -->
      <v-alert
        v-if="mostImportantCluster"
        type="info"
        variant="tonal"
        color="primary"
        class="mb-6"
      >
        The most important cluster is:
        <b class="text-primary">{{ mostImportantCluster }}</b>
      </v-alert>

      <!-- Cluster selector (multiple) -->
      <v-select
        v-model="localSelectedCluster"
        v-if="allIps?.length"
        :items="allIps"
        label="Select Cluster(s) to analyze"
        multiple
        chips
        small-chips
        outlined
        class="mb-4"
      />
    </v-card>

    <!-- ──────── NAVIGATION ──────── -->
    <div class="d-flex ga-4 mb-6">
      <v-btn
        color="primary"
        @click="$emit('next')"
        :disabled="loading"
        class="control-btn"
      >
        Continue <v-icon end>mdi-arrow-right</v-icon>
      </v-btn>
    </div>
    <!-- ──────── HIERARCHY TABLE ──────── -->
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
        <template v-slot:item.score="{ item }">{{ item.score }}</template>
        <template v-slot:item.total_packets="{ item }">
          {{ item.traffic_score }}
        </template>
        <template v-slot:item.unique_ips="{ item }">
          {{ item.unique_partners_sum }}
        </template>
      </v-data-table>
      <v-card-text class="text-caption mt-2">
        <strong>Note:</strong> Each field in the table represents the following:
        <ul class="mb-0 pl-4">
          <li><b>Cluster:</b> The ID number of the cluster.</li>
          <li>
            <b>Score:</b> Overall importance of the cluster based on both
            network connectivity and traffic. Higher values indicate more
            central or active clusters.
          </li>
          <li>
            <b>Total Packets:</b> The traffic volume component for the cluster,
            calculated as the logarithm of the total packets sent and received.
            This smooths out large differences so very active clusters do not
            dominate the score.
          </li>
          <li>
            <b>Unique IPs:</b> The sum of distinct IP addresses that the cluster
            communicates with. It measures how connected the cluster is within
            the network.
          </li>
        </ul>
      </v-card-text>
    </v-card>

    <!-- ──────── SAVE RESULTS ──────── -->
    <v-card class="pa-6 rounded-xl connection-card">
      <h4 class="text-subtitle-1 font-weight-bold mb-3 text-primary">
        <v-icon color="primary" class="mr-2">mdi-content-save</v-icon>
        Save Clustering Results
      </h4>

      <v-select
        class="futuristic-input mb-4"
        :items="['json', 'csv']"
        label="Choose File Type"
        v-model="localFileType"
      />

      <v-btn @click="saveResults" color="green" class="white--text control-btn">
        <v-icon start>mdi-content-save</v-icon>
        Save Results ({{ localFileType.toUpperCase() }})
      </v-btn>
    </v-card>
    <v-card class="pa-6 mt-8 rounded-xl connection-card">
      <h4 class="text-subtitle-1 font-weight-bold mb-4 text-primary">
        <v-icon color="deep-purple-accent-4" class="mr-2">
          mdi-chart-line
        </v-icon>
        Cluster Modularity Analysis
      </h4>
      <ModularityChart
        v-if="modularityData.length > 1"
        :modularityData="modularityData"
      />
    </v-card>
  </div>
</template>

<script>
import NetworkGraph from "@/components/NetworkGraph.vue";
import ModularityChart from "@/components/ModularityChart.vue";

export default {
  components: { NetworkGraph, ModularityChart },

  props: {
    filename: String,
    loading: Boolean,
    graphData: Object,
    networkGraphKey: Number,
    noOfclusters: Number,
    noOfclustersList: Array,
    suggestedClusters: [Number, String],
    mostImportantCluster: [Number, String],
    allIps: Array,
    selectedCluster: Array,
    elbowData: Array,
    clusterHierarchy: Array,
    headers: Array,
    fileType: String,
    modularityData: Array,
    best_k: Number,
    best_modularity: Number,
  },

  emits: [
    "next",
    "update:noOfclusters",
    "update:selectedCluster",
    "save-results",
  ],

  data() {
    return {
      localClusters: this.noOfclusters,
      localSelectedCluster: this.selectedCluster || [],
      localFileType: this.fileType,
    };
  },

  watch: {
    noOfclusters(val) {
      this.localClusters = val;
    },
    fileType(val) {
      this.localFileType = val;
    },
    selectedCluster(val) {
      this.localSelectedCluster = val;
    },
  },

  methods: {
    async onClustersChange() {
      this.$emit("update:noOfclusters", this.localClusters);
      // parent will call fetchAnalysis()
    },

    async saveResults() {
      this.$emit("save-results", { fileType: this.localFileType });
    },
  },

  // keep the two-way binding in sync
  created() {
    this.$watch("localClusters", (v) => this.$emit("update:noOfclusters", v));
    this.$watch("localSelectedCluster", (v) =>
      this.$emit("update:selectedCluster", v)
    );
    this.$watch("localFileType", (v) => this.$emit("update:fileType", v));
  },
};
</script>
