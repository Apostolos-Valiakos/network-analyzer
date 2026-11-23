<template>
  <v-card class="elevation-4 rounded-xl pa-6 mb-8 connection-card">
    <h3 class="text-h5 font-weight-bold mb-4 text-primary">
      <v-icon color="primary" class="mr-2" size="large">mdi-brain</v-icon>
      Live Rule Based Analysis
    </h3>

    <v-alert v-if="error" type="error" class="mb-4">{{ error }}</v-alert>

    <div class="d-flex align-center mb-6">
      <v-btn
        color="primary"
        @click="run"
        :loading="loading"
        :disabled="loading"
        class="white--text control-btn"
      >
        <v-icon>mdi-send-circle</v-icon> Run Analysis on Latest Slice
      </v-btn>
      <v-progress-linear
        v-if="loading"
        indeterminate
        color="deep-purple-accent-4"
        class="ml-4 rounded-lg"
        height="10"
      ></v-progress-linear>
    </div>

    <template v-if="results">
      <v-row class="mb-6">
        <v-col v-for="(val, key) in overview" :key="key" cols="12" sm="6" md="4">
          <v-card class="pa-4 status-card text-center" elevation="4">
            <div
              class="text-caption text-white text-opacity-80 text-uppercase font-weight-bold mb-1"
            >
              {{ labels[key] }}
            </div>
            <div class="text-h4 font-weight-black text-white">
              {{ val }}
            </div>
          </v-card>
        </v-col>
      </v-row>

      <v-card
        class="pa-4 mb-6 rounded-xl elevation-2"
        v-if="chartData.length"
      >
        <PieChart :chartData="chartData" chartTitle="Role Distribution Summary" />
      </v-card>

      <h4 class="text-h6 font-weight-bold mb-3">Identified Roles</h4>
      <v-data-table
        :headers="headers"
        :items="tableItems"
        class="packet-table elevation-2 rounded-lg"
      >
        <template v-slot:item.class_name="{ item }">
          <div class="d-flex align-center font-weight-bold">
            <v-avatar size="24" color="primary" class="mr-2"
              ><span class="text-caption">{{
                item.class_name.charAt(0)
              }}</span></v-avatar
            >
            {{ item.class_name }}
          </div>
        </template>
        <template v-slot:item.percentage="{ item }">
          <div class="d-flex align-center" style="width: 100%">
            <v-progress-linear
              :value="item.percentage"
              color="primary"
              height="8"
              rounded
              striped
              class="mr-2"
            ></v-progress-linear>
            <span class="text-caption text-medium-emphasis font-weight-bold"
              >{{ item.percentage }}%</span
            >
          </div>
        </template>
        <template v-slot:item.ips="{ item }">
          <div v-if="item.ips && item.ips.length" class="py-2">
            <v-chip
              v-for="ip in item.ips"
              :key="ip"
              color="primary"
              class="mr-1 mb-1 font-weight-bold shadow-sm"
              >{{ ip }}</v-chip
            >
          </div>
          <div v-else class="text-grey text-caption font-italic">
            No IPs assigned
          </div>
        </template>
      </v-data-table>
    </template>
  </v-card>
</template>

<script>
import PieChart from "@/components/PieChart.vue";

export default {
  name: "LiveAnalysisPanel",
  components: { PieChart },
  data() {
    return {
      loading: false,
      results: null,
      error: null,
      labels: {
        most_frequent_class: "Most Frequent Class",
        total_classified: "Total Classified IPs",
        processing_time: "Processing Time",
      },
      headers: [
        {
          text: "Role / Class Name",
          value: "class_name",
          align: "start",
          width: "25%",
        },
        { text: "Count", value: "count", sortable: true, width: "15%" },
        {
          text: "Distribution",
          value: "percentage",
          align: "center",
          width: "20%",
        },
        { text: "Assigned IP Addresses", value: "ips", sortable: false },
      ],
    };
  },
  computed: {
    summary() {
      return this.results?.rule_based_classification_summary || [];
    },
    overview() {
      if (!this.results) return {};
      return {
        most_frequent_class: this.results.most_frequent_class || "N/A",
        total_classified: this.results.total_classified || 0,
        processing_time: this.results.processing_time
          ? `${this.results.processing_time.toFixed(2)}s`
          : "0s",
      };
    },
    tableItems() {
      const total = this.summary.reduce((sum, item) => sum + item.count, 0);
      return this.summary.map((item) => ({
        ...item,
        percentage: total > 0 ? ((item.count / total) * 100).toFixed(1) : 0,
      }));
    },
    chartData() {
      return this.summary.map((item) => ({
        name: item.class_name,
        value: item.count,
      }));
    },
  },
  methods: {
    async run() {
      this.loading = true;
      this.error = null;
      try {
        const response = await this.$apiFetch(this.$api.url("/v1/analyze_live"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        const data = await response.json();
        if (!response.ok)
          throw new Error(data.message || "Failed to analyze live PCAP.");
        this.results = data;
        // The scan panel can target the IPs this analysis found
        const ips = new Set();
        this.summary.forEach((item) => (item.ips || []).forEach((ip) => ips.add(ip)));
        this.$emit("analyzed", Array.from(ips));
      } catch (error) {
        this.error = error.message;
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>

<style scoped>
.status-card {
  background: var(--status-card-bg) !important;
}
.connection-card {
  border: 1px solid var(--connection-border) !important;
}
.control-btn {
  border-radius: 12px !important;
  font-weight: bold;
  letter-spacing: 0.5px;
}
.packet-table >>> .v-data-table__wrapper {
  border-radius: 8px;
}
</style>
