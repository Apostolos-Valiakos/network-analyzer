<template>
  <v-container class="pa-6" style="max-width: 960px">
    <div class="d-flex align-center mb-6">
      <v-icon size="32" color="primary" class="mr-3">mdi-file-upload-outline</v-icon>
      <div>
        <h1 class="text-h5 font-weight-bold mb-0">Upload PCAP for Full Analysis</h1>
        <p class="text-caption mb-0 text-dim">
          Saved and fully analyzed in one step — stats, UE, clustering, ML roles.
        </p>
      </div>
    </div>

    <v-card class="themed-card rounded-xl pa-5 mb-6">
      <v-file-input
        v-model="file"
        label="Select .pcap file"
        outlined
        dense
        prepend-inner-icon="mdi-file-outline"
        show-size
        accept=".pcap"
        hide-details
        @change="handleFile"
      />
      <v-btn
        :disabled="!file"
        :loading="loading"
        color="primary"
        class="mt-4"
        @click="runFullAnalysis"
      >
        <v-icon left>mdi-play-circle-outline</v-icon>
        Analyse
      </v-btn>
    </v-card>

    <div v-if="analysis">
      <v-alert
        v-if="loadedFromCache"
        type="info"
        dense
        class="mb-4"
        border="left"
      >
        Loaded previous results from this browser. Upload a new file to replace
        them.
      </v-alert>

      <v-card class="themed-accent-card rounded-xl pa-5 mb-5">
        <div class="d-flex align-center">
          <v-icon color="primary" class="mr-3">mdi-package-variant</v-icon>
          <span class="text-h6 font-weight-bold">Total Packets: <span class="primary--text">{{ analysis.total_packets }}</span></span>
        </div>
      </v-card>

      <div class="d-flex flex-wrap btn-gap">
        <v-btn
          color="success"
          @click="saveRoles('json')"
          :loading="savingJson"
        >
          <v-icon left>mdi-code-json</v-icon>
          Save Roles as JSON
        </v-btn>
        <v-btn color="success" @click="saveRoles('csv')" :loading="savingCsv">
          <v-icon left>mdi-table</v-icon>
          Save Roles as CSV
        </v-btn>
        <v-btn text @click="clearCachedResults">
          <v-icon left>mdi-trash-can-outline</v-icon>
          Clear cached results
        </v-btn>
      </div>
    </div>
  </v-container>
</template>

<script>
import Assessments from "@/components/Assessments.vue";
import NetworkGraph from "@/components/NetworkGraph.vue";

export default {
  components: { Assessments, NetworkGraph },

  data() {
    return {
      cacheKey: "analyze:latest",
      file: null,
      loading: false,
      savingJson: false,
      savingCsv: false,
      filename: null,
      analysis: null,
      graphData: null,
      ueInfo: null,
      roles: null,
      clustering: null,
      suggested_clusters: null,
      response: null,
      apiBaseUrl: process.env.API_BASE_URL || "http://127.0.0.1:5555",
      loadedFromCache: false,

      // Table
      ipProtocolHeaders: [
        { text: "IP Address", value: "ip" },
        { text: "Protocols Sent", value: "protocols" },
      ],
      expanded: [],
    };
  },

  computed: {
    ipProtocolItems() {
      if (!this.analysis?.ip_protocols) return [];
      return Object.entries(this.analysis.ip_protocols).map(
        ([ip, protocols]) => ({
          ip,
          protocols,
        })
      );
    },
  },

  methods: {
    handleFile(f) {
      this.file = f;
    },
    loadCachedResults() {
      try {
        const raw = localStorage.getItem(this.cacheKey);
        if (!raw) return;
        const cached = JSON.parse(raw);
        this.filename = cached.filename || null;
        this.analysis = cached.analysis || null;
        this.graphData = cached.graphData || null;
        this.ueInfo = cached.ueInfo || null;
        this.roles = cached.roles || null;
        this.clustering = cached.clustering || null;
        this.suggested_clusters = cached.suggested_clusters || null;
        this.response = cached.response || null;
        if (this.analysis) this.loadedFromCache = true;
      } catch (e) {
        localStorage.removeItem(this.cacheKey);
      }
    },
    cacheResults(data) {
      const payload = {
        filename: data.filename,
        analysis: data.analysis,
        graphData: data.analysis?.graph || null,
        ueInfo: data.ue_sessions || null,
        roles: data.roles || null,
        clustering: data.clustering || null,
        suggested_clusters: data.suggested_clusters || null,
        response: data,
      };
      localStorage.setItem(this.cacheKey, JSON.stringify(payload));
      this.loadedFromCache = false;
    },
    clearCachedResults() {
      localStorage.removeItem(this.cacheKey);
      this.loadedFromCache = false;
    },
    async runFullAnalysis() {
      if (!this.file) return;
      this.loading = true;

      const form = new FormData();
      form.append("file", this.file);

      try {
        const resp = await this.$apiFetch(`${this.apiBaseUrl}/automated-analysis`, {
          method: "POST",
          body: form,
        });

        const data = await resp.json();
        this.response = await data;

        if (!resp.ok) {
          throw new Error(data.error || "Analysis failed");
        }

        // Populate all sections
        this.filename = data.filename;
        this.analysis = data.analysis;
        this.graphData = data.analysis.graph;
        this.ueInfo = data.ue_sessions;
        this.roles = data.roles;
        this.clustering = data.clustering;
        this.suggested_clusters = data.suggested_clusters;
        this.response = data;
        this.cacheResults(data);
      } catch (err) {
        alert(`Analysis failed: ${err.message}`);
      } finally {
        this.loading = false;
      }
    },

    async saveRoles(type) {
      if (!this.filename) return;

      if (type === "json") this.savingJson = true;
      if (type === "csv") this.savingCsv = true;

      const url = `${this.apiBaseUrl}/save_roles?file=${this.filename}&type=${type}`;

      try {
        const resp = await this.$apiFetch(url);
        if (!resp.ok) {
          const err = await resp.json();
          throw new Error(err.error || "Save failed");
        }

        const blob = await resp.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = `roles_${this.filename.split("_").pop()}.${type}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(downloadUrl);
      } catch (err) {
        alert(`Save ${type.toUpperCase()} failed: ${err.message}`);
      } finally {
        this.savingJson = false;
        this.savingCsv = false;
      }
    },
  },
  mounted() {
    this.loadCachedResults();
  },
};
</script>

<style scoped>
.themed-card {
  border: 1px solid var(--border) !important;
}
.themed-accent-card {
  border: 1px solid var(--accent-border) !important;
}
.btn-gap { gap: 12px; }
</style>
