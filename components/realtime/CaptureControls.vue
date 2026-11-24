<template>
  <v-card class="data-card pa-4" elevation="0">
    <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
      Capture Controls
    </v-card-title>
    <div class="d-flex align-center mb-4 gap-3">
      <v-btn
        :disabled="!connected"
        color="info"
        depressed
        class="control-btn"
        @click="$emit('get-interfaces')"
      >
        <v-icon left>mdi-network-outline</v-icon>
        Get Interfaces
      </v-btn>
      <v-select
        :value="selectedInterface"
        :items="interfaces"
        label="Select Interface"
        dense
        outlined
        :disabled="!connected || capturing || interfaces.length === 0"
        class="flex-grow-1"
        hide-details
        @change="$emit('select-interface', $event)"
      ></v-select>
    </div>

    <div class="controls-section">
      <v-btn
        :disabled="!connected || capturing || generating || !currentInterface"
        color="green"
        depressed
        class="control-btn white--text"
        @click="$emit('start')"
      >
        <v-icon left>mdi-play-circle-outline</v-icon>
        Start
      </v-btn>
      <v-btn
        :disabled="!connected || generating"
        color="orange"
        depressed
        class="control-btn white--text"
        @click="$emit('stop')"
      >
        <v-icon left>mdi-stop-circle-outline</v-icon>
        Stop
      </v-btn>
      <v-btn
        :disabled="capturing || generating"
        color="red"
        outlined
        class="control-btn"
        @click="$emit('clear')"
      >
        <v-icon left>mdi-delete-outline</v-icon>
        Clear
      </v-btn>
      <v-btn
        :disabled="!packetCount || sending"
        color="purple"
        large
        depressed
        class="control-btn white--text"
        @click="$emit('visualize')"
      >
        <v-icon left>mdi-network-outline</v-icon>
        Visualize
      </v-btn>
      <v-btn
        :disabled="!packetCount || sending || generating"
        color="blue"
        large
        depressed
        class="control-btn white--text mb-4"
        @click="$emit('analyze')"
      >
        <v-icon left>mdi-chart-areaspline</v-icon>
        {{ generating ? "Preparing..." : "Analyze" }}
      </v-btn>
    </div>
  </v-card>
</template>

<script>
// Interface selection and the capture buttons. State lives in the page; this
// component only shows it and emits the user's actions.
export default {
  name: "CaptureControls",
  props: {
    connected: { type: Boolean, default: false },
    capturing: { type: Boolean, default: false },
    generating: { type: Boolean, default: false },
    sending: { type: Boolean, default: false },
    packetCount: { type: Number, default: 0 },
    interfaces: { type: Array, default: () => [] },
    selectedInterface: { type: String, default: null },
    currentInterface: { type: String, default: null },
  },
};
</script>

<style scoped>
.data-card {
  border: 1px solid var(--border) !important;
  background-color: var(--surface) !important;
  border-radius: 16px !important;
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
.gap-3 {
  gap: 12px;
}
</style>
