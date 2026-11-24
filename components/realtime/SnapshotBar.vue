<template>
  <div class="realtime-view">
    <v-btn
      :disabled="disabled"
      color="primary"
      large
      depressed
      class="control-btn"
      @click="$emit('generate')"
    >
      <v-icon left>mdi-download</v-icon>
      {{ generating ? "Saving snapshot..." : "Generate PCAP" }}
    </v-btn>
    <div v-if="downloadLink" class="mt-2">
      <a :href="downloadLink" :download="filename">Download PCAP</a>
    </div>
  </div>
</template>

<script>
// Saves the packets captured so far as a PCAP while the capture keeps running.
export default {
  name: "SnapshotBar",
  props: {
    disabled: { type: Boolean, default: false },
    generating: { type: Boolean, default: false },
    downloadLink: { type: String, default: null },
    filename: { type: String, default: null },
  },
};
</script>

<style scoped>
.realtime-view {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 24px;
  padding: 16px;
  border: 1px dashed var(--highlight-border);
  border-radius: 16px;
  background: var(--highlight-bg);
}
.control-btn {
  border-radius: 16px !important;
  font-weight: 700;
  text-transform: none;
  letter-spacing: 0.5px;
}
</style>
