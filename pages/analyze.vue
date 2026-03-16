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
        <h3 class="text-h6 mb-2">Privacy Metrics</h3>
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

        <div class="mb-4 d-flex align-center">
          <v-btn small text color="primary" @click="privacyInfoDialog = true">
            <v-icon small class="mr-1">mdi-information-outline</v-icon>
            Privacy Transformation Info
          </v-btn>
        </div>

        <v-dialog v-model="privacyInfoDialog" max-width="760">
          <v-card>
            <v-card-title class="text-h6">Privacy Transformation Info</v-card-title>
            <v-card-text>
              <div class="option-line">
                <b>Pseudonymization</b> replaces direct values (like IPs) with stable tokens (e.g. <code>ps_xxx</code>) while keeping row linkage.
              </div>
              <div class="option-line"><b>Deterministic:</b> same input always maps to same token.</div>
              <div class="option-line"><b>Per-run:</b> stable only for current computation, changes next run.</div>
              <div class="option-line"><b>Per-pilot:</b> stable within each pilot value, different across pilots.</div>
              <div class="option-line mt-2">
                <b>Generalization</b> makes values less specific (IP masks, numeric bins, text prefixes, protocol families) to increase anonymity.
              </div>
              <div class="option-line mt-2">
                <b>Suppression</b> masks selected values as <code>*</code>; threshold suppression hides low-frequency values.
              </div>
            </v-card-text>
            <v-card-actions>
              <v-spacer />
              <v-btn text color="primary" @click="privacyInfoDialog = false">Close</v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>

        <v-expansion-panels v-model="privacyPanels" multiple flat class="mb-4">
          <v-expansion-panel>
            <v-expansion-panel-header>
              <span class="font-weight-medium">Pseudonymization</span>
            </v-expansion-panel-header>
            <v-expansion-panel-content>
              <v-select
                v-model="privacyPseudonymize"
                :items="privacyColumns"
                label="Pseudonymize Columns"
                multiple
                chips
                outlined
                dense
                class="mb-2"
              />
              <v-select
                v-model="privacyPseudonymizationMode"
                :items="pseudonymizationModeOptions"
                item-text="text"
                item-value="value"
                label="Pseudonymization Mode"
                outlined
                dense
              />
            </v-expansion-panel-content>
          </v-expansion-panel>

          <v-expansion-panel>
            <v-expansion-panel-header>
              <span class="font-weight-medium">Generalization</span>
            </v-expansion-panel-header>
            <v-expansion-panel-content>
              <v-select
                v-model="privacyGeneralize"
                :items="privacyColumns"
                label="Generalize Columns"
                multiple
                chips
                outlined
                dense
                class="mb-2"
              />
              <v-select
                v-for="col in privacyGeneralize"
                :key="`gen-${col}`"
                v-model="privacyGeneralizeProfiles[col]"
                :items="generalizationProfileOptions"
                item-text="text"
                item-value="value"
                :label="`Profile for ${col}`"
                outlined
                dense
                class="mb-2"
              />
              <v-alert dense outlined type="info" class="mt-2">
                Auto: by data type, IP /24 and /16: subnet/network grouping, Numeric bins 5/10: range buckets, Text prefix 1/3: partial masking, Protocol family: TCP/SCTP/UDP/OTHER.
              </v-alert>
            </v-expansion-panel-content>
          </v-expansion-panel>

          <v-expansion-panel>
            <v-expansion-panel-header>
              <span class="font-weight-medium">Suppression</span>
            </v-expansion-panel-header>
            <v-expansion-panel-content>
              <v-select
                v-model="privacySuppress"
                :items="privacyColumns"
                label="Suppress Columns"
                multiple
                chips
                outlined
                dense
                class="mb-2"
              />
              <v-text-field
                v-model.number="privacySuppressThreshold"
                type="number"
                min="2"
                label="Suppression threshold (min frequency)"
                outlined
                dense
              />
            </v-expansion-panel-content>
          </v-expansion-panel>
        </v-expansion-panels>

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
        <v-alert
          v-if="privacySuggestions.length"
          type="warning"
          dense
          outlined
          class="mb-4"
        >
          <div class="mb-1"><b>Suggestions</b></div>
          <ul class="suggestions">
            <li v-for="(item, idx) in privacySuggestions" :key="`sug-${idx}`">
              {{ item }}
            </li>
          </ul>
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
      privacyInfoDialog: false,
      privacyPanels: [0, 1, 2],
      privacyIdentifiers: [],
      privacySensitiveAttribute: null,
      privacyPseudonymize: [],
      privacyPseudonymizationMode: "deterministic",
      privacyGeneralize: [],
      privacySuppress: [],
      privacyGeneralizeProfiles: {},
      privacySuppressThreshold: 2,
      privacyLoading: false,
      privacyError: "",
      privacySuggestions: [],
      privacyOriginalMetrics: null,
      privacyTransformedMetrics: null,
      privacyTransformedRecords: [],
      generalizationProfileOptions: [
        { text: "Auto", value: "auto" },
        { text: "IP Mask /24", value: "ip_mask_24" },
        { text: "IP Mask /16", value: "ip_mask_16" },
        { text: "Numeric bins (size 5)", value: "numeric_bins_5" },
        { text: "Numeric bins (size 10)", value: "numeric_bins_10" },
        { text: "Text prefix (1 char)", value: "text_prefix_1" },
        { text: "Text prefix (3 chars)", value: "text_prefix_3" },
        { text: "Protocol family", value: "protocol_family" },
      ],
      pseudonymizationModeOptions: [
        { text: "Deterministic", value: "deterministic" },
        { text: "Per-run", value: "per_run" },
        { text: "Per-pilot", value: "per_pilot" },
      ],

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
    suppressThresholdMap() {
      const threshold = Math.max(2, Number(this.privacySuppressThreshold) || 2);
      return this.privacySuppress.reduce((acc, col) => {
        acc[col] = threshold;
        return acc;
      }, {});
    },
  },
  watch: {
    privacyGeneralize: {
      immediate: true,
      handler(cols) {
        const next = {};
        cols.forEach((col) => {
          next[col] = this.privacyGeneralizeProfiles[col] || "auto";
        });
        this.privacyGeneralizeProfiles = next;
      },
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
      this.privacySuggestions = [];

      try {
        const baseline = await this.callPrivacyMetrics({
          pseudonymize: [],
          generalize: [],
          suppress: [],
          generalize_profiles: {},
          suppress_thresholds: {},
        });
        const transformed = await this.callPrivacyMetrics({
          pseudonymize: this.privacyPseudonymize,
          pseudonymization_mode: this.privacyPseudonymizationMode,
          generalize: this.privacyGeneralize,
          suppress: this.privacySuppress,
          generalize_profiles: this.privacyGeneralizeProfiles,
          suppress_thresholds: this.suppressThresholdMap,
        });

        this.privacyOriginalMetrics = baseline.metrics;
        this.privacyTransformedMetrics = transformed.metrics;
        this.privacyTransformedRecords = transformed.records.slice(0, 12);
        this.privacySuggestions = transformed.suggestions || [];
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

.suggestions {
  margin: 0;
  padding-left: 18px;
}

.option-line {
  font-size: 0.92rem;
  margin-bottom: 4px;
}

.privacy-option-card {
  height: 100%;
}

.privacy-option-grid .v-col {
  display: flex;
}
</style>
