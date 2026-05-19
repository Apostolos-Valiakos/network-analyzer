<template>
  <v-container class="pa-6" style="max-width: 900px">
    <div class="d-flex align-center mb-6">
      <v-icon size="32" color="primary" class="mr-3">mdi-graph-outline</v-icon>
      <div>
        <h1 class="text-h5 font-weight-bold mb-0">Network Graph Visualizer</h1>
        <p class="text-caption mb-0 text-dim">
          Select a .json file to visualize the network graph
        </p>
      </div>
    </div>

    <v-card class="themed-card rounded-xl pa-5 mb-6">
      <v-file-input
        v-model="file"
        label="Select a .json file"
        outlined
        dense
        prepend-inner-icon="mdi-file-code-outline"
        show-size
        accept=".json"
        hide-details
        @change="handleFile"
      />
    </v-card>

    <NetworkGraph v-if="graphData" :graphData="graphData" />
  </v-container>
</template>

<script>
import NetworkGraph from "@/components/NetworkGraph.vue";

export default {
  components: {
    NetworkGraph,
  },
  data() {
    return {
      file: null,
      graphData: null,
    };
  },
  methods: {
    handleFile(file) {
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const json = JSON.parse(e.target.result);
          this.graphData = json;
        } catch (err) {
          console.error("Invalid JSON file", err);
          this.graphData = null;
        }
      };
      reader.readAsText(file);
    },
  },
};
</script>

<style scoped>
.themed-card {
  border: 1px solid var(--border) !important;
}
</style>
