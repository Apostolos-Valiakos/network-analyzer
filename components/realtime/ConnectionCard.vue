<template>
  <v-card class="status-card mb-6" elevation="0">
    <v-card-text class="pa-4">
      <div class="d-flex align-center justify-space-between">
        <div class="d-flex align-center">
          <v-icon :color="connected ? 'success' : 'error'" class="mr-3" size="28">
            {{ connected ? "mdi-link" : "mdi-link-off" }}
          </v-icon>
          <div class="text-h6 font-weight-bold">
            Connection Status:
            <span :class="connected ? 'success--text' : 'error--text'">
              {{ connected ? "Connected" : "Disconnected" }}
            </span>
          </div>
        </div>
        <v-btn :disabled="connected" color="secondary" outlined @click="$emit('connect')">
          Connect
        </v-btn>
      </div>
      <v-text-field
        :value="url"
        label="WebSocket URL"
        :disabled="connected"
        dense
        outlined
        class="mt-4"
        prepend-icon="mdi-web"
        hide-details
        @input="$emit('update:url', $event)"
      ></v-text-field>
    </v-card-text>
  </v-card>
</template>

<script>
// The sensor's packet stream (publisher.py): address and connection state.
export default {
  name: "ConnectionCard",
  props: {
    connected: { type: Boolean, default: false },
    url: { type: String, default: "" },
  },
};
</script>

<style scoped>
.status-card {
  border: 1px solid var(--accent-border) !important;
  background-color: var(--surface) !important;
  border-radius: 16px !important;
}
</style>
