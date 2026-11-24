<template>
  <v-card class="pa-4 data-card" elevation="0">
    <v-card-title class="text-subtitle-1 font-weight-bold mb-3">
      Packet Log (Last 10)
    </v-card-title>
    <v-list dense class="packet-list">
      <v-list-item v-for="(packet, index) in packets" :key="index" class="packet-item">
        <v-list-item-content>
          <v-list-item-title class="text-caption font-mono">
            {{ packet.timestamp }} - {{ packet.length }} bytes
          </v-list-item-title>
          <v-list-item-subtitle class="text-truncate text-monospace">
            {{ packet.preview }}
          </v-list-item-subtitle>
        </v-list-item-content>
      </v-list-item>
    </v-list>
  </v-card>
</template>

<script>
export default {
  name: "PacketLog",
  props: {
    packets: { type: Array, default: () => [] },
  },
};
</script>

<style scoped>
.data-card {
  border: 1px solid var(--border) !important;
  background-color: var(--surface) !important;
  border-radius: 16px !important;
}
.packet-list {
  background-color: var(--highlight-bg);
  border-radius: 12px;
  padding: 8px;
}
.packet-item {
  border-bottom: 1px solid var(--packet-item-border);
  padding: 8px 0;
}
.packet-item:last-child {
  border-bottom: none;
}
.font-mono {
  font-family: monospace;
}
</style>
