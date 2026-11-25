<template>
  <div>
    <div class="d-flex align-center flex-wrap mb-3">
      <h4 class="text-h6 font-weight-bold mr-4">Roles per IP</h4>
      <v-select
        v-if="hasK8s"
        v-model="namespace"
        :items="namespaceItems"
        label="Namespace"
        dense
        outlined
        hide-details
        class="namespace-filter"
      ></v-select>
    </div>
    <v-data-table
      :headers="headers"
      :items="filteredItems"
      item-key="ip"
      show-expand
      :expanded.sync="expanded"
      dense
      class="packet-table elevation-2"
    >
      <template v-slot:item.confidence="{ item }">
        {{ formatConfidence(item.confidence) }}
      </template>
      <template v-slot:item.pod="{ item }">
        <span v-if="item.podLabel">{{ item.podLabel }}</span>
        <span v-else class="grey--text">—</span>
      </template>
      <template v-slot:item.hint="{ item }">
        <v-chip
          v-if="item.mismatch"
          x-small
          color="warning"
          class="font-weight-bold"
          :title="'The pod suggests ' + item.hintRole + ', the traffic says ' + item.role"
        >
          <v-icon x-small left>mdi-alert</v-icon>
          pod suggests {{ item.hintRole }}
        </v-chip>
        <v-chip
          v-else-if="item.suggestedRole"
          x-small
          outlined
          color="primary"
          :title="'No traffic evidence; the pod suggests ' + item.suggestedRole"
        >
          suggested {{ item.suggestedRole }}
        </v-chip>
        <v-chip v-else-if="item.hintRole" x-small outlined color="success">
          pod agrees
        </v-chip>
      </template>
      <template v-slot:expanded-item="{ headers: cols, item }">
        <td :colspan="cols.length" class="pa-3 text-body-2">
          {{ item.reasoning }}
        </td>
      </template>
    </v-data-table>
  </div>
</template>

<script>
// Per-IP role results: role, confidence and reasoning from the traffic, plus,
// when Hubble data is available, the pod behind the IP and what the pod's
// labels suggest (k8s.hint_role / suggested_role / k8s_mismatch).
const ALL = "All namespaces";

export default {
  name: "RoleDetailsTable",
  props: {
    // {ip: {role, confidence, reasoning, k8s?}}
    details: { type: Object, default: () => ({}) },
  },
  data() {
    return { expanded: [], namespace: ALL };
  },
  computed: {
    items() {
      return Object.keys(this.details)
        .sort()
        .map((ip) => {
          const d = this.details[ip] || {};
          const k8s = d.k8s || {};
          let podLabel = "";
          if (k8s.pod) podLabel = (k8s.namespace ? k8s.namespace + "/" : "") + k8s.pod;
          else if (k8s.service) podLabel = "Service " + k8s.service;
          return {
            ip,
            role: d.role,
            confidence: d.confidence,
            reasoning: d.reasoning,
            namespace: k8s.namespace || "",
            podLabel,
            hintRole: k8s.hint_role || "",
            suggestedRole: k8s.suggested_role || "",
            mismatch: Boolean(k8s.k8s_mismatch),
          };
        });
    },
    hasK8s() {
      return this.items.some((item) => item.podLabel);
    },
    namespaceItems() {
      const names = Array.from(new Set(this.items.map((i) => i.namespace).filter(Boolean))).sort();
      return [ALL].concat(names);
    },
    filteredItems() {
      if (this.namespace === ALL) return this.items;
      return this.items.filter((item) => item.namespace === this.namespace);
    },
    headers() {
      const headers = [
        { text: "IP Address", value: "ip" },
        { text: "Role", value: "role" },
        { text: "Confidence", value: "confidence" },
      ];
      if (this.hasK8s) {
        headers.push({ text: "Pod", value: "pod", sortable: false });
        headers.push({ text: "Kubernetes hint", value: "hint", sortable: false });
      }
      headers.push({ text: "", value: "data-table-expand" });
      return headers;
    },
  },
  methods: {
    formatConfidence(value) {
      return typeof value === "number" ? value.toFixed(2) : "—";
    },
  },
};
</script>

<style scoped>
.namespace-filter {
  max-width: 260px;
}
</style>
