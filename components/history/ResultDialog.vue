<template>
  <v-dialog :value="value" max-width="720" scrollable @input="$emit('input', $event)">
    <v-card class="rounded-xl" style="border: 1px solid var(--border)">
      <v-card-title class="d-flex align-center">
        <v-icon color="primary" class="mr-2">mdi-chart-box-outline</v-icon>
        Analysis Results
        <v-spacer />
        <v-btn icon small @click="$emit('input', false)">
          <v-icon>mdi-close</v-icon>
        </v-btn>
      </v-card-title>
      <v-divider />
      <v-card-text class="pt-4" style="max-height: 560px">
        <div v-if="loading" class="d-flex justify-center py-8">
          <v-progress-circular indeterminate color="primary" />
        </div>
        <div v-else-if="data">
          <!-- Problems stored with the result (partial analysis) -->
          <warnings-alert :warnings="data.warnings || []" />

          <!-- PCAP analysis result -->
          <template v-if="type === 'pcap'">
            <v-row class="mb-4">
              <v-col cols="12" sm="4">
                <div class="metric-box pa-4 rounded-lg">
                  <div class="text-caption text-dim mb-1">Total Packets</div>
                  <div class="text-h5 font-weight-bold primary--text">
                    {{ data.total_packets }}
                  </div>
                </div>
              </v-col>
              <v-col cols="12" sm="4">
                <div class="metric-box pa-4 rounded-lg">
                  <div class="text-caption text-dim mb-1">Unique IPs</div>
                  <div class="text-h5 font-weight-bold primary--text">
                    {{ Object.keys(data.roles || {}).length }}
                  </div>
                </div>
              </v-col>
              <v-col cols="12" sm="4">
                <div class="metric-box pa-4 rounded-lg">
                  <div class="text-caption text-dim mb-1">Graph Nodes</div>
                  <div class="text-h5 font-weight-bold primary--text">
                    {{ (data.graph && data.graph.nodes && data.graph.nodes.length) || 0 }}
                  </div>
                </div>
              </v-col>
            </v-row>

            <RoleDetailsTable v-if="data.role_details" :details="data.role_details" />
            <div v-else-if="data.roles && Object.keys(data.roles).length">
              <div class="text-subtitle-2 font-weight-bold mb-2">IP Role Assignments</div>
              <v-simple-table dense class="rounded-lg" style="border: 1px solid var(--border)">
                <thead>
                  <tr>
                    <th>IP Address</th>
                    <th>Role</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(info, ip) in data.roles" :key="ip">
                    <td class="font-mono">{{ ip }}</td>
                    <td>
                      <v-chip x-small color="primary" outlined>
                        {{ info.role || info }}
                      </v-chip>
                    </td>
                    <td>{{ formatConfidence(info.confidence) }}</td>
                  </tr>
                </tbody>
              </v-simple-table>
            </div>
          </template>

          <!-- Cluster result -->
          <template v-else-if="type === 'cluster'">
            <div v-if="data.clusterSummary">
              <v-row class="mb-4">
                <v-col cols="6" sm="3">
                  <div class="metric-box pa-4 rounded-lg">
                    <div class="text-caption text-dim mb-1">Best k</div>
                    <div class="text-h5 font-weight-bold primary--text">
                      {{ data.clusterSummary.best_k }}
                    </div>
                  </div>
                </v-col>
                <v-col cols="6" sm="3">
                  <div class="metric-box pa-4 rounded-lg">
                    <div class="text-caption text-dim mb-1">Modularity</div>
                    <div class="text-h5 font-weight-bold primary--text">
                      {{ (data.clusterSummary.best_modularity || 0).toFixed(3) }}
                    </div>
                  </div>
                </v-col>
              </v-row>
            </div>
            <div v-if="data.clusters && data.clusters.length">
              <div class="text-subtitle-2 font-weight-bold mb-2">Clusters</div>
              <v-simple-table dense class="rounded-lg" style="border: 1px solid var(--border)">
                <thead>
                  <tr>
                    <th>Cluster</th>
                    <th>Score</th>
                    <th>Packets</th>
                    <th>Unique IPs</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="c in data.clusters" :key="c.cluster">
                    <td>{{ c.cluster }}</td>
                    <td>{{ c.score }}</td>
                    <td>{{ c.total_packets }}</td>
                    <td>{{ c.unique_ips }}</td>
                  </tr>
                </tbody>
              </v-simple-table>
            </div>
          </template>
        </div>
        <div v-else class="text-center text-dim py-8">No result data available.</div>
      </v-card-text>
    </v-card>
  </v-dialog>
</template>

<script>
import RoleDetailsTable from "@/components/RoleDetailsTable.vue";
import WarningsAlert from "@/components/WarningsAlert.vue";
import { formatConfidence } from "@/utils/history";

// A stored analysis ('pcap') or clustering ('cluster') result. v-model opens it.
export default {
  name: "ResultDialog",
  components: { RoleDetailsTable, WarningsAlert },
  props: {
    value: { type: Boolean, default: false },
    type: { type: String, default: null },
    data: { type: Object, default: null },
    loading: { type: Boolean, default: false },
  },
  methods: { formatConfidence },
};
</script>

<style scoped>
.metric-box {
  background: var(--metric-box-bg);
  border: 1px solid var(--metric-box-border);
  text-align: center;
}
.font-mono {
  font-family: "Courier New", Courier, monospace;
  font-size: 0.82rem;
}
</style>
