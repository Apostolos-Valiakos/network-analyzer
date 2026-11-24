<template>
  <v-card class="rounded-xl" style="border: 1px solid var(--border)">
    <v-data-table
      :headers="headers"
      :items="items"
      :loading="loading"
      :items-per-page="15"
      :no-data-text="noDataText"
      class="history-table"
    >
      <template #[`item.original_filename`]="{ item }">
        <span class="font-weight-medium">
          {{ item.original_filename || (nameFallback ? item.filename : "") || "—" }}
        </span>
      </template>
      <template #[`item.upload_time`]="{ item }">
        {{ formatDate(item.upload_time) }}
      </template>
      <template #[`item.created_at`]="{ item }">
        {{ formatDate(item.created_at) }}
      </template>
      <template #[`item.file_size`]="{ item }">
        {{ formatSize(item.file_size) }}
      </template>
      <template #[`item.status`]="{ item }">
        <v-chip x-small :color="statusColor(item.status)" dark>{{ item.status }}</v-chip>
      </template>
      <template #[`item.actions`]="{ item }">
        <div class="d-flex" style="gap: 4px">
          <v-tooltip v-for="action in shownActions" :key="action.key" bottom>
            <template #activator="{ on }">
              <v-btn
                icon
                x-small
                :color="action.color"
                :disabled="action.disabled(item)"
                :loading="action.key === 'reanalyze' && busyId === item.id"
                v-on="on"
                @click="$emit(action.key, item)"
              >
                <v-icon small>{{ action.icon }}</v-icon>
              </v-btn>
            </template>
            <span>{{ action.label }}</span>
          </v-tooltip>
        </div>
      </template>
    </v-data-table>
  </v-card>
</template>

<script>
import { formatDate, formatSize, statusColor } from "@/utils/history";

// Every action a History row can offer; each tab picks some, in this order,
// and the table emits the action's key with the row.
const ACTIONS = {
  view: { icon: "mdi-eye-outline", label: "View Results", disabled: (item) => !item.has_result },
  reanalyze: { icon: "mdi-refresh", label: "Re-run Analysis" },
  cluster: { icon: "mdi-chart-scatter-plot", label: "Open in Clustering" },
  recluster: { icon: "mdi-refresh", label: "Re-cluster", disabled: (item) => !item.pcap_id },
  download: { icon: "mdi-download", label: "Download PCAP" },
  delete: { icon: "mdi-delete-outline", label: "Delete", color: "error" },
};

export default {
  name: "HistoryTable",
  props: {
    headers: { type: Array, required: true },
    items: { type: Array, default: () => [] },
    loading: { type: Boolean, default: false },
    noDataText: { type: String, default: "No data" },
    actions: { type: Array, default: () => [] },
    busyId: { type: [String, Number], default: null },
    // Show the stored file name when there is no original name (pcaps only;
    // a cluster result's file name is internal).
    nameFallback: { type: Boolean, default: true },
  },
  computed: {
    shownActions() {
      return this.actions.map((key) => ({
        key,
        color: undefined,
        disabled: () => false,
        ...ACTIONS[key],
      }));
    },
  },
  methods: { formatDate, formatSize, statusColor },
};
</script>

<style scoped>
.history-table {
  border-radius: 12px;
}
</style>
