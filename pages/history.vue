<template>
  <v-container class="pa-6" style="max-width: 1200px">

    <!-- Header -->
    <div class="d-flex align-center mb-6">
      <v-icon size="32" color="primary" class="mr-3">mdi-history</v-icon>
      <div>
        <h1 class="text-h5 font-weight-bold mb-0">File History</h1>
        <p class="text-caption mb-0 text-dim">
          View, re-run, download or delete your uploaded and generated files.
        </p>
      </div>
    </div>

    <!-- Tabs -->
    <v-tabs v-model="tab" background-color="transparent" color="primary" class="mb-4">
      <v-tab>
        <v-icon left small>mdi-file-upload-outline</v-icon>
        Uploaded PCAPs
        <v-chip x-small class="ml-2" color="primary" outlined>{{ pcaps.length }}</v-chip>
      </v-tab>
      <v-tab>
        <v-icon left small>mdi-access-point</v-icon>
        Generated PCAPs
        <v-chip x-small class="ml-2" color="primary" outlined>{{ generated.length }}</v-chip>
      </v-tab>
      <v-tab>
        <v-icon left small>mdi-chart-scatter-plot</v-icon>
        Cluster Results
        <v-chip x-small class="ml-2" color="primary" outlined>{{ clusters.length }}</v-chip>
      </v-tab>
    </v-tabs>

    <v-tabs-items v-model="tab">

      <!-- ── Tab 1: Uploaded PCAPs ───────────────────────── -->
      <v-tab-item>
        <v-card class="rounded-xl" style="border: 1px solid var(--border)">
          <v-data-table
            :headers="pcapHeaders"
            :items="pcaps"
            :loading="loadingPcaps"
            :items-per-page="15"
            no-data-text="No uploaded PCAPs found."
            class="history-table"
          >
            <template #[`item.original_filename`]="{ item }">
              <span class="font-weight-medium">{{ item.original_filename || item.filename }}</span>
            </template>
            <template #[`item.upload_time`]="{ item }">
              {{ formatDate(item.upload_time) }}
            </template>
            <template #[`item.file_size`]="{ item }">
              {{ formatSize(item.file_size) }}
            </template>
            <template #[`item.status`]="{ item }">
              <v-chip x-small :color="statusColor(item.status)" dark>{{ item.status }}</v-chip>
            </template>
            <template #[`item.actions`]="{ item }">
              <div class="d-flex" style="gap:4px">
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small :disabled="!item.has_result" v-on="on"
                      @click="viewPcapResult(item)">
                      <v-icon small>mdi-eye-outline</v-icon>
                    </v-btn>
                  </template>
                  <span>View Results</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small v-on="on" :loading="reanalyzing === item.id"
                      @click="reanalyze(item)">
                      <v-icon small>mdi-refresh</v-icon>
                    </v-btn>
                  </template>
                  <span>Re-run Analysis</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small v-on="on"
                      @click="$router.push({ path: '/clustering', query: { id: item.filename } })">
                      <v-icon small>mdi-chart-scatter-plot</v-icon>
                    </v-btn>
                  </template>
                  <span>Open in Clustering</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small v-on="on" @click="downloadPcap(item.filename)">
                      <v-icon small>mdi-download</v-icon>
                    </v-btn>
                  </template>
                  <span>Download PCAP</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small color="error" v-on="on"
                      @click="confirmDelete('pcap', item)">
                      <v-icon small>mdi-delete-outline</v-icon>
                    </v-btn>
                  </template>
                  <span>Delete</span>
                </v-tooltip>
              </div>
            </template>
          </v-data-table>
        </v-card>
      </v-tab-item>

      <!-- ── Tab 2: Generated PCAPs ─────────────────────── -->
      <v-tab-item>
        <v-card class="rounded-xl" style="border: 1px solid var(--border)">
          <v-data-table
            :headers="pcapHeaders"
            :items="generated"
            :loading="loadingGenerated"
            :items-per-page="15"
            no-data-text="No generated PCAPs found."
            class="history-table"
          >
            <template #[`item.original_filename`]="{ item }">
              <span class="font-weight-medium">{{ item.original_filename || item.filename }}</span>
            </template>
            <template #[`item.upload_time`]="{ item }">
              {{ formatDate(item.upload_time) }}
            </template>
            <template #[`item.file_size`]="{ item }">
              {{ formatSize(item.file_size) }}
            </template>
            <template #[`item.status`]="{ item }">
              <v-chip x-small :color="statusColor(item.status)" dark>{{ item.status }}</v-chip>
            </template>
            <template #[`item.actions`]="{ item }">
              <div class="d-flex" style="gap:4px">
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small v-on="on"
                      @click="$router.push({ path: '/clustering', query: { id: item.filename } })">
                      <v-icon small>mdi-chart-scatter-plot</v-icon>
                    </v-btn>
                  </template>
                  <span>Open in Clustering</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small v-on="on" @click="downloadPcap(item.filename)">
                      <v-icon small>mdi-download</v-icon>
                    </v-btn>
                  </template>
                  <span>Download PCAP</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small color="error" v-on="on"
                      @click="confirmDelete('pcap', item)">
                      <v-icon small>mdi-delete-outline</v-icon>
                    </v-btn>
                  </template>
                  <span>Delete</span>
                </v-tooltip>
              </div>
            </template>
          </v-data-table>
        </v-card>
      </v-tab-item>

      <!-- ── Tab 3: Cluster Results ──────────────────────── -->
      <v-tab-item>
        <v-card class="rounded-xl" style="border: 1px solid var(--border)">
          <v-data-table
            :headers="clusterHeaders"
            :items="clusters"
            :loading="loadingClusters"
            :items-per-page="15"
            no-data-text="No cluster results found."
            class="history-table"
          >
            <template #[`item.original_filename`]="{ item }">
              <span class="font-weight-medium">{{ item.original_filename || '—' }}</span>
            </template>
            <template #[`item.created_at`]="{ item }">
              {{ formatDate(item.created_at) }}
            </template>
            <template #[`item.actions`]="{ item }">
              <div class="d-flex" style="gap:4px">
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small :disabled="!item.has_result" v-on="on"
                      @click="viewClusterResult(item)">
                      <v-icon small>mdi-eye-outline</v-icon>
                    </v-btn>
                  </template>
                  <span>View Results</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small :disabled="!item.pcap_id" v-on="on"
                      @click="openInClustering(item)">
                      <v-icon small>mdi-refresh</v-icon>
                    </v-btn>
                  </template>
                  <span>Re-cluster</span>
                </v-tooltip>
                <v-tooltip bottom>
                  <template #activator="{ on }">
                    <v-btn icon x-small color="error" v-on="on"
                      @click="confirmDelete('cluster', item)">
                      <v-icon small>mdi-delete-outline</v-icon>
                    </v-btn>
                  </template>
                  <span>Delete</span>
                </v-tooltip>
              </div>
            </template>
          </v-data-table>
        </v-card>
      </v-tab-item>

    </v-tabs-items>

    <!-- ── Delete confirmation dialog ─────────────────── -->
    <v-dialog v-model="deleteDialog" max-width="420" persistent>
      <v-card class="rounded-xl pa-2" style="border: 1px solid var(--border)">
        <v-card-title class="text-h6">
          <v-icon color="error" class="mr-2">mdi-alert-circle-outline</v-icon>
          Confirm Delete
        </v-card-title>
        <v-card-text>
          This will permanently delete
          <strong>{{ deleteTarget && (deleteTarget.original_filename || deleteTarget.filename) }}</strong>
          and its file on disk. This cannot be undone.
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn text @click="deleteDialog = false">Cancel</v-btn>
          <v-btn color="error" :loading="deleting" @click="executeDelete">Delete</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- ── Analysis result viewer dialog ──────────────── -->
    <v-dialog v-model="resultDialog" max-width="720" scrollable>
      <v-card class="rounded-xl" style="border: 1px solid var(--border)">
        <v-card-title class="d-flex align-center">
          <v-icon color="primary" class="mr-2">mdi-chart-box-outline</v-icon>
          Analysis Results
          <v-spacer />
          <v-btn icon small @click="resultDialog = false">
            <v-icon>mdi-close</v-icon>
          </v-btn>
        </v-card-title>
        <v-divider />
        <v-card-text class="pt-4" style="max-height: 560px">
          <div v-if="resultLoading" class="d-flex justify-center py-8">
            <v-progress-circular indeterminate color="primary" />
          </div>
          <div v-else-if="resultData">

            <!-- PCAP analysis result -->
            <template v-if="resultType === 'pcap'">
              <v-row class="mb-4">
                <v-col cols="12" sm="4">
                  <div class="metric-box pa-4 rounded-lg">
                    <div class="text-caption text-dim mb-1">Total Packets</div>
                    <div class="text-h5 font-weight-bold primary--text">
                      {{ resultData.total_packets }}
                    </div>
                  </div>
                </v-col>
                <v-col cols="12" sm="4">
                  <div class="metric-box pa-4 rounded-lg">
                    <div class="text-caption text-dim mb-1">Unique IPs</div>
                    <div class="text-h5 font-weight-bold primary--text">
                      {{ Object.keys(resultData.roles || {}).length }}
                    </div>
                  </div>
                </v-col>
                <v-col cols="12" sm="4">
                  <div class="metric-box pa-4 rounded-lg">
                    <div class="text-caption text-dim mb-1">Graph Nodes</div>
                    <div class="text-h5 font-weight-bold primary--text">
                      {{ (resultData.graph && resultData.graph.nodes && resultData.graph.nodes.length) || 0 }}
                    </div>
                  </div>
                </v-col>
              </v-row>

              <div v-if="resultData.roles && Object.keys(resultData.roles).length">
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
                    <tr v-for="(info, ip) in resultData.roles" :key="ip">
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
            <template v-else-if="resultType === 'cluster'">
              <div v-if="resultData.clusterSummary">
                <v-row class="mb-4">
                  <v-col cols="6" sm="3">
                    <div class="metric-box pa-4 rounded-lg">
                      <div class="text-caption text-dim mb-1">Best k</div>
                      <div class="text-h5 font-weight-bold primary--text">
                        {{ resultData.clusterSummary.best_k }}
                      </div>
                    </div>
                  </v-col>
                  <v-col cols="6" sm="3">
                    <div class="metric-box pa-4 rounded-lg">
                      <div class="text-caption text-dim mb-1">Modularity</div>
                      <div class="text-h5 font-weight-bold primary--text">
                        {{ (resultData.clusterSummary.best_modularity || 0).toFixed(3) }}
                      </div>
                    </div>
                  </v-col>
                </v-row>
              </div>
              <div v-if="resultData.clusters && resultData.clusters.length">
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
                    <tr v-for="c in resultData.clusters" :key="c.cluster">
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

    <!-- Snackbar -->
    <v-snackbar v-model="snackbar.show" :color="snackbar.color" timeout="3500" top right>
      {{ snackbar.text }}
    </v-snackbar>

  </v-container>
</template>

<script>
export default {
  data() {
    return {
      tab: 0,
      apiBaseUrl: process.env.VUE_APP_API_BASE_URL || 'http://127.0.0.1:5555',

      pcaps: [],
      generated: [],
      clusters: [],

      loadingPcaps: false,
      loadingGenerated: false,
      loadingClusters: false,

      reanalyzing: null,

      deleteDialog: false,
      deleteType: null,
      deleteTarget: null,
      deleting: false,

      resultDialog: false,
      resultType: null,
      resultData: null,
      resultLoading: false,

      snackbar: { show: false, text: '', color: 'success' },
    }
  },

  computed: {
    isAdmin() {
      return this.$store.state.auth.isAdmin
    },
    pcapHeaders() {
      const base = [
        { text: 'File', value: 'original_filename', sortable: true },
        { text: 'Uploaded', value: 'upload_time', sortable: true },
        { text: 'Size', value: 'file_size', sortable: true },
        { text: 'Status', value: 'status', sortable: false },
        { text: 'Actions', value: 'actions', sortable: false, align: 'right' },
      ]
      if (this.isAdmin) {
        base.splice(4, 0, { text: 'User', value: 'username', sortable: true })
      }
      return base
    },
    clusterHeaders() {
      const base = [
        { text: 'Source PCAP', value: 'original_filename', sortable: true },
        { text: 'Created', value: 'created_at', sortable: true },
        { text: 'Actions', value: 'actions', sortable: false, align: 'right' },
      ]
      if (this.isAdmin) {
        base.splice(2, 0, { text: 'User', value: 'username', sortable: true })
      }
      return base
    },
  },

  mounted() {
    this.loadAll()
  },

  methods: {
    async loadAll() {
      this.loadPcaps()
      this.loadGenerated()
      this.loadClusters()
    },

    async loadPcaps() {
      this.loadingPcaps = true
      try {
        const r = await this.$apiFetch(`${this.apiBaseUrl}/v1/history/pcaps`)
        this.pcaps = await r.json()
      } catch {
        this.toast('Failed to load uploaded PCAPs', 'error')
      } finally {
        this.loadingPcaps = false
      }
    },

    async loadGenerated() {
      this.loadingGenerated = true
      try {
        const r = await this.$apiFetch(`${this.apiBaseUrl}/v1/history/generated`)
        this.generated = await r.json()
      } catch {
        this.toast('Failed to load generated PCAPs', 'error')
      } finally {
        this.loadingGenerated = false
      }
    },

    async loadClusters() {
      this.loadingClusters = true
      try {
        const r = await this.$apiFetch(`${this.apiBaseUrl}/v1/history/clusters`)
        this.clusters = await r.json()
      } catch {
        this.toast('Failed to load cluster results', 'error')
      } finally {
        this.loadingClusters = false
      }
    },

    async viewPcapResult(item) {
      this.resultType = 'pcap'
      this.resultData = null
      this.resultDialog = true
      this.resultLoading = true
      try {
        const r = await this.$apiFetch(`${this.apiBaseUrl}/v1/history/pcap/${item.id}/result`)
        if (!r.ok) throw new Error()
        this.resultData = await r.json()
      } catch {
        this.toast('Could not load results', 'error')
        this.resultDialog = false
      } finally {
        this.resultLoading = false
      }
    },

    async viewClusterResult(item) {
      this.resultType = 'cluster'
      this.resultData = null
      this.resultDialog = true
      this.resultLoading = true
      try {
        const r = await this.$apiFetch(`${this.apiBaseUrl}/v1/history/cluster/${item.id}/result`)
        if (!r.ok) throw new Error()
        this.resultData = await r.json()
      } catch {
        this.toast('Could not load results', 'error')
        this.resultDialog = false
      } finally {
        this.resultLoading = false
      }
    },

    async reanalyze(item) {
      this.reanalyzing = item.id
      try {
        const r = await this.$apiFetch(
          `${this.apiBaseUrl}/v1/history/pcap/${item.id}/reanalyze`,
          { method: 'POST' }
        )
        if (!r.ok) {
          const err = await r.json()
          throw new Error(err.error || 'Analysis failed')
        }
        item.has_result = true
        item.status = 'COMPLETED'
        this.toast('Re-analysis complete')
      } catch (e) {
        this.toast(e.message, 'error')
      } finally {
        this.reanalyzing = null
      }
    },

    openInClustering(item) {
      // Look up the pcap filename from the pcaps list
      const pcap = this.pcaps.find(p => p.id === item.pcap_id)
        || this.generated.find(p => p.id === item.pcap_id)
      if (pcap) {
        this.$router.push({ path: '/clustering', query: { id: pcap.filename } })
      } else {
        this.toast('Source PCAP not found in history', 'warning')
      }
    },

    confirmDelete(type, item) {
      this.deleteType = type
      this.deleteTarget = item
      this.deleteDialog = true
    },

    async executeDelete() {
      this.deleting = true
      const { deleteType: type, deleteTarget: item } = this
      const url = type === 'pcap'
        ? `${this.apiBaseUrl}/v1/history/pcap/${item.id}`
        : `${this.apiBaseUrl}/v1/history/cluster/${item.id}`
      try {
        const r = await this.$apiFetch(url, { method: 'DELETE' })
        if (!r.ok) throw new Error()
        if (type === 'pcap') {
          this.pcaps = this.pcaps.filter(p => p.id !== item.id)
          this.generated = this.generated.filter(p => p.id !== item.id)
        } else {
          this.clusters = this.clusters.filter(c => c.id !== item.id)
        }
        this.toast('Deleted successfully')
      } catch {
        this.toast('Delete failed', 'error')
      } finally {
        this.deleting = false
        this.deleteDialog = false
      }
    },

    async downloadPcap(filename) {
      try {
        const r = await this.$apiFetch(`${this.apiBaseUrl}/generated_pcaps/${filename}`)
        if (!r.ok) throw new Error('Download failed')
        const blob = await r.blob()
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      } catch {
        this.toast('Download failed', 'error')
      }
    },

    formatDate(iso) {
      if (!iso) return '—'
      return new Date(iso).toLocaleString()
    },

    formatSize(bytes) {
      if (!bytes) return '—'
      if (bytes < 1024) return `${bytes} B`
      if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
      return `${(bytes / 1048576).toFixed(1)} MB`
    },

    statusColor(s) {
      if (!s) return 'grey'
      const m = { COMPLETED: 'success', PROCESSING: 'warning', PENDING: 'grey', ERROR: 'error' }
      return m[s.toUpperCase()] || 'grey'
    },

    formatConfidence(v) {
      if (v == null) return '—'
      return `${(v * 100).toFixed(0)}%`
    },

    toast(text, color = 'success') {
      this.snackbar = { show: true, text, color }
    },
  },
}
</script>

<style scoped>
.history-table {
  border-radius: 12px;
}
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
