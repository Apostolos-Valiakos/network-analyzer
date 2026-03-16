<template>
  <v-container class="pa-4">
    <div>
      <h1 class="text-h5 mb-4">Upload PCAP for Full Analysis</h1>
      <h5 class="text-disabled mb-2 grey--text">
        The file is saved and fully analyzed in one step (stats, UE, clustering,
        ML roles).
      </h5>
    </div>

    <v-file-input
      v-model="file"
      label="Select .pcap file"
      filled
      prepend-icon="mdi-file"
      show-size
      accept=".pcap"
      @change="handleFile"
    ></v-file-input>

    <v-btn
      :disabled="!file"
      :loading="loading"
      color="primary"
      class="mt-4"
      @click="runFullAnalysis"
    >
      Analyse
    </v-btn>

    <div v-if="analysis" class="mt-8">
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
      <!-- Packet Stats -->
      <v-card class="mb-6 pa-4" outlined>
        <h3>Total Packets: {{ analysis.total_packets }}</h3>
      </v-card>

      <v-card class="mb-6 pa-4" outlined>
        <h3 class="text-h6 mb-2">Privacy Metrics & Pilot Relevance</h3>
        <p class="mb-4 grey--text text--darken-1">
          Select identifiers and sensitive attributes, then test
          pseudonymization, generalization, and suppression to improve
          k-anonymity, l-diversity, and t-closeness.
        </p>

        <v-row>
          <v-col cols="12" md="6">
            <v-select
              v-model="privacyIdentifiers"
              :items="privacyColumns"
              label="Identifiers (quasi-identifiers)"
              multiple
              chips
              outlined
              dense
            />
          </v-col>
          <v-col cols="12" md="6">
            <v-select
              v-model="privacySensitiveAttribute"
              :items="privacyColumns"
              label="Sensitive Attribute"
              outlined
              dense
            />
          </v-col>
        </v-row>

        <v-row>
          <v-col cols="12" md="4">
            <v-select
              v-model="privacyPseudonymize"
              :items="privacyColumns"
              label="Pseudonymize Columns"
              multiple
              chips
              outlined
              dense
            />
          </v-col>
          <v-col cols="12" md="4">
            <v-select
              v-model="privacyGeneralize"
              :items="privacyColumns"
              label="Generalize Columns"
              multiple
              chips
              outlined
              dense
            />
          </v-col>
          <v-col cols="12" md="4">
            <v-select
              v-model="privacySuppress"
              :items="privacyColumns"
              label="Suppress Columns"
              multiple
              chips
              outlined
              dense
            />
          </v-col>
        </v-row>

        <v-btn
          color="primary"
          class="mb-4"
          :disabled="!canComputePrivacy"
          :loading="privacyLoading"
          @click="computePrivacyMetrics"
        >
          Compute Privacy Metrics
        </v-btn>

        <v-alert v-if="privacyError" type="error" dense class="mb-4">
          {{ privacyError }}
        </v-alert>

        <v-row v-if="privacyOriginalMetrics && privacyTransformedMetrics">
          <v-col cols="12" md="6">
            <v-card outlined class="pa-3">
              <h4 class="mb-2">Before Transformations</h4>
              <div class="metric-line">
                k-anonymity: {{ privacyOriginalMetrics.k_anonymity }}
              </div>
              <div class="metric-line">
                l-diversity: {{ privacyOriginalMetrics.l_diversity }}
              </div>
              <div class="metric-line">
                t-closeness: {{ privacyOriginalMetrics.t_closeness }}
              </div>
            </v-card>
          </v-col>
          <v-col cols="12" md="6">
            <v-card outlined class="pa-3">
              <h4 class="mb-2">After Transformations</h4>
              <div class="metric-line">
                k-anonymity: {{ privacyTransformedMetrics.k_anonymity }}
              </div>
              <div class="metric-line">
                l-diversity: {{ privacyTransformedMetrics.l_diversity }}
              </div>
              <div class="metric-line">
                t-closeness: {{ privacyTransformedMetrics.t_closeness }}
              </div>
            </v-card>
          </v-col>
        </v-row>

        <div v-if="privacyTransformedRecords.length" class="mt-4">
          <h4 class="mb-2">Transformed Records Preview</h4>
          <v-data-table
            :headers="privacyTableHeaders"
            :items="privacyTransformedRecords"
            dense
            hide-default-footer
          />
        </div>
      </v-card>

      <div class="mt-4">
        <v-btn
          color="success"
          class="mr-3"
          @click="saveRoles('json')"
          :loading="savingJson"
        >
          Save Roles as JSON
        </v-btn>
        <v-btn color="success" @click="saveRoles('csv')" :loading="savingCsv">
          Save Roles as CSV
        </v-btn>
        <v-btn text class="ml-3" @click="clearCachedResults">
          Clear cached results
        </v-btn>
      </div>
    </div>
  </v-container>
</template>

<script>
export default {
  data() {
    return {
      cacheKey: "analyze:latest",
      file: null,
      loading: false,
      savingJson: false,
      savingCsv: false,

      // Results from backend
      filename: null,
      analysis: null,
      graphData: null,
      ueInfo: null,
      roles: null,
      clustering: null,
      suggested_clusters: null,
      response: null,
      apiBaseUrl: process.env.API_BASE_URL,
      loadedFromCache: false,
      privacyIdentifiers: [],
      privacySensitiveAttribute: null,
      privacyPseudonymize: [],
      privacyGeneralize: [],
      privacySuppress: [],
      privacyLoading: false,
      privacyError: "",
      privacyOriginalMetrics: null,
      privacyTransformedMetrics: null,
      privacyTransformedRecords: [],

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
    privacyRecords() {
      const ipRoles = this.response?.ip_roles || {};
      const ipProtocols = this.analysis?.ip_protocols || {};
      const allIps = new Set([
        ...Object.keys(ipRoles),
        ...Object.keys(ipProtocols),
      ]);

      return Array.from(allIps).map((ip) => {
        const protocols = ipProtocols[ip] || [];
        return {
          ip,
          role: ipRoles[ip] || "Unknown",
          protocol_count: protocols.length,
          protocols: protocols.join("|"),
          pilot: "PUC#1",
        };
      });
    },
    privacyColumns() {
      if (!this.privacyRecords.length) return [];
      return Object.keys(this.privacyRecords[0]);
    },
    canComputePrivacy() {
      return (
        this.privacyRecords.length > 0 &&
        this.privacyIdentifiers.length > 0 &&
        !!this.privacySensitiveAttribute
      );
    },
    privacyTableHeaders() {
      return this.privacyColumns.map((col) => ({
        text: col.replace(/_/g, " "),
        value: col,
      }));
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
        roles: data.roles || data.ip_roles || null,
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
        const resp = await fetch(`${this.apiBaseUrl}/automated-analysis`, {
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
        this.roles = data.roles || data.ip_roles;
        this.clustering = data.clustering;
        this.suggested_clusters = data.suggested_clusters;
        this.response = data;
        this.cacheResults(data);
        console.log(data);
        console.log(data.roles);
      } catch (err) {
        alert(`Analysis failed: ${err.message}`);
      } finally {
        this.loading = false;
      }
    },
    async callPrivacyMetrics(transformations) {
      const resp = await fetch(`${this.apiBaseUrl}/privacy-metrics`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          records: this.privacyRecords,
          identifiers: this.privacyIdentifiers,
          sensitive_attribute: this.privacySensitiveAttribute,
          transformations,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || "Privacy metrics failed");
      }
      return data;
    },
    async computePrivacyMetrics() {
      if (!this.canComputePrivacy) return;
      this.privacyLoading = true;
      this.privacyError = "";

      try {
        const baseline = await this.callPrivacyMetrics({
          pseudonymize: [],
          generalize: [],
          suppress: [],
        });
        const transformed = await this.callPrivacyMetrics({
          pseudonymize: this.privacyPseudonymize,
          generalize: this.privacyGeneralize,
          suppress: this.privacySuppress,
        });

        this.privacyOriginalMetrics = baseline.metrics;
        this.privacyTransformedMetrics = transformed.metrics;
        this.privacyTransformedRecords = transformed.records.slice(0, 12);
      } catch (err) {
        this.privacyError = err.message;
      } finally {
        this.privacyLoading = false;
      }
    },

    async saveRoles(type) {
      if (!this.filename) return;

      if (type === "json") this.savingJson = true;
      if (type === "csv") this.savingCsv = true;

      const url = `${this.apiBaseUrl}/save_roles?file=${this.filename}&type=${type}`;

      try {
        const resp = await fetch(url);
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
.v-card {
  border-radius: 8px;
}

.metric-line {
  font-size: 0.95rem;
  margin-bottom: 4px;
}
</style>
