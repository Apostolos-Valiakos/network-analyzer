<template>
  <v-card class="pa-4 data-card" elevation="0">
    <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
      Network Graph (Preview)
    </v-card-title>
    <v-card-text class="pa-4 text-center">
      <v-skeleton-loader v-if="loading" type="image" height="300" />
      <NetworkGraph v-if="graphData && !loading" :key="graphKey" :graphData="graphData" />
    </v-card-text>
  </v-card>
</template>

<script>
import NetworkGraph from "@/components/NetworkGraph.vue";

export default {
  name: "GraphPreview",
  components: { NetworkGraph },
  props: {
    graphData: { type: Object, default: null },
    loading: { type: Boolean, default: false },
    graphKey: { type: Number, default: 0 },
  },
};
</script>

<style scoped>
.data-card {
  border: 1px solid var(--border) !important;
  background-color: var(--surface) !important;
  border-radius: 16px !important;
}
</style>
