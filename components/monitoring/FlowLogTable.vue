<template>
  <v-card class="elevation-4 rounded-xl pa-4">
    <div class="d-flex justify-space-between align-center mb-4">
      <h3 class="text-h6">Network Flow Logs</h3>
      <v-text-field
        v-model="search"
        append-icon="mdi-magnify"
        label="Search IP or Protocol"
        single-line
        hide-details
        style="max-width: 300px"
      ></v-text-field>
    </div>
    <v-data-table
      :headers="headers"
      :items="stats"
      :search="search"
      class="elevation-0"
      :items-per-page="5"
    >
      <template v-slot:item.ts="{ item }">{{
        new Date(item.ts * 1000).toLocaleTimeString()
      }}</template>
      <template v-slot:item.orig_bytes="{ item }">{{
        formatBytes(item.orig_bytes)
      }}</template>
      <template v-slot:item.resp_bytes="{ item }">{{
        formatBytes(item.resp_bytes)
      }}</template>
      <template v-slot:item.conn_state="{ item }">
        <v-chip
          :color="
            item.conn_state === 'S0'
              ? 'warning'
              : item.conn_state === 'REJ'
              ? 'error'
              : 'success'
          "
          >{{ item.conn_state }}</v-chip
        >
      </template>
    </v-data-table>
  </v-card>
</template>

<script>
import { formatBytes } from "@/utils/format";

export default {
  name: "FlowLogTable",
  props: {
    stats: { type: Array, required: true },
  },
  data() {
    return {
      search: "",
      headers: [
        { text: "Time", value: "ts" },
        { text: "Source IP", value: "id.orig_h" },
        { text: "Dest IP", value: "id.resp_h" },
        { text: "Protocol", value: "proto" },
        { text: "State", value: "conn_state" },
        { text: "Bytes Out", value: "orig_bytes" },
        { text: "Bytes In", value: "resp_bytes" },
      ],
    };
  },
  methods: { formatBytes },
};
</script>
