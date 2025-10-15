<template>
  <v-container class="pa-4">
    <h1 class="text-h5 mb-4">Select a .json file to visualize network graph</h1>

    <!-- File Picker -->
    <v-file-input
      v-model="file"
      label="Select a .json file to vizualise"
      filled
      prepend-icon="mdi-file"
      show-size
      accept=".json"
      @change="handleFile"
    ></v-file-input>

    <!-- Graph is displayed only after graphData is loaded -->
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
