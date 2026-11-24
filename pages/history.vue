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
      <v-tab-item>
        <HistoryTable
          :headers="pcapHeaders"
          :items="pcaps"
          :loading="loadingPcaps"
          no-data-text="No uploaded PCAPs found."
          :actions="['view', 'reanalyze', 'cluster', 'download', 'delete']"
          :busy-id="reanalyzing"
          @view="viewPcapResult"
          @reanalyze="reanalyze"
          @cluster="openPcapInClustering"
          @download="downloadPcap($event.filename)"
          @delete="confirmDelete('pcap', $event)"
        />
      </v-tab-item>

      <v-tab-item>
        <HistoryTable
          :headers="pcapHeaders"
          :items="generated"
          :loading="loadingGenerated"
          no-data-text="No generated PCAPs found."
          :actions="['cluster', 'download', 'delete']"
          @cluster="openPcapInClustering"
          @download="downloadPcap($event.filename)"
          @delete="confirmDelete('pcap', $event)"
        />
      </v-tab-item>

      <v-tab-item>
        <HistoryTable
          :headers="clusterHeaders"
          :items="clusters"
          :loading="loadingClusters"
          no-data-text="No cluster results found."
          :actions="['view', 'recluster', 'delete']"
          :name-fallback="false"
          @view="viewClusterResult"
          @recluster="openInClustering"
          @delete="confirmDelete('cluster', $event)"
        />
      </v-tab-item>
    </v-tabs-items>

    <DeleteDialog
      v-model="deleteDialog"
      :name="deleteTarget ? deleteTarget.original_filename || deleteTarget.filename : ''"
      :loading="deleting"
      @confirm="executeDelete"
    />

    <ResultDialog
      v-model="resultDialog"
      :type="resultType"
      :data="resultData"
      :loading="resultLoading"
    />

    <!-- Snackbar -->
    <v-snackbar v-model="snackbar.show" :color="snackbar.color" timeout="3500" top right>
      {{ snackbar.text }}
    </v-snackbar>

  </v-container>
</template>

<script>
import DeleteDialog from "@/components/history/DeleteDialog.vue";
import HistoryTable from "@/components/history/HistoryTable.vue";
import ResultDialog from "@/components/history/ResultDialog.vue";
import { clusterHeaders, pcapHeaders } from "@/utils/history";

export default {
  components: { DeleteDialog, HistoryTable, ResultDialog },

  data() {
    return {
      tab: 0,

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
      return pcapHeaders(this.isAdmin)
    },
    clusterHeaders() {
      return clusterHeaders(this.isAdmin)
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
        this.pcaps = await this.$api.json(`/v1/history/pcaps`)
      } catch {
        this.toast('Failed to load uploaded PCAPs', 'error')
      } finally {
        this.loadingPcaps = false
      }
    },

    async loadGenerated() {
      this.loadingGenerated = true
      try {
        this.generated = await this.$api.json(`/v1/history/generated`)
      } catch {
        this.toast('Failed to load generated PCAPs', 'error')
      } finally {
        this.loadingGenerated = false
      }
    },

    async loadClusters() {
      this.loadingClusters = true
      try {
        this.clusters = await this.$api.json(`/v1/history/clusters`)
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
        this.resultData = await this.$api.json(`/v1/history/pcap/${item.id}/result`)
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
        this.resultData = await this.$api.json(`/v1/history/cluster/${item.id}/result`)
      } catch {
        this.toast('Could not load results', 'error')
        this.resultDialog = false
      } finally {
        this.resultLoading = false
      }
    },

    // Stays on $apiFetch: a 500 means the analysis ran and failed, and the
    // row is then shown as ERROR.
    async reanalyze(item) {
      this.reanalyzing = item.id
      try {
        const r = await this.$apiFetch(
          this.$api.url(`/v1/history/pcap/${item.id}/reanalyze`),
          { method: 'POST' }
        )
        const body = await r.json().catch(() => ({}))
        if (!r.ok) {
          // 500 = analysis ran and failed; the backend marked the file ERROR
          if (r.status === 500) item.status = 'ERROR'
          throw new Error(body.error || 'Analysis failed')
        }
        item.has_result = true
        item.status = 'COMPLETED'
        const warnings = body.warnings || []
        if (warnings.length) {
          this.toast(`Re-analysis complete, with problems: ${warnings.join(' ')}`, 'warning')
        } else {
          this.toast('Re-analysis complete')
        }
      } catch (e) {
        this.toast(e.message, 'error')
      } finally {
        this.reanalyzing = null
      }
    },

    openPcapInClustering(item) {
      this.$router.push({ path: '/clustering', query: { id: item.filename } })
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
      const path = type === 'pcap'
        ? `/v1/history/pcap/${item.id}`
        : `/v1/history/cluster/${item.id}`
      try {
        await this.$api.json(path, { method: 'DELETE' })
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
        const r = await this.$apiFetch(this.$api.url(`/generated_pcaps/${filename}`))
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

    toast(text, color = 'success') {
      this.snackbar = { show: true, text, color }
    },
  },
}
</script>
