<template>
  <div>
    <v-card class="pa-6 mb-8 rounded-xl connection-card">
      <h3 class="text-h6 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-brain</v-icon>
        Rule Based Analysis
      </h3>

      <v-alert v-if="cnnError" type="error" class="mb-4" text>
        {{ cnnError }}
      </v-alert>

      <div class="d-flex align-center mb-4">
        <v-btn
          color="primary"
          large
          @click="startAnalysis"
          :loading="cnnLoading"
          :disabled="cnnLoading"
          class="white--text control-btn"
        >
          <v-icon start>mdi-send-circle</v-icon>
          Start Rule Based Analysis
        </v-btn>

        <v-progress-linear
          v-if="cnnLoading"
          indeterminate
          color="deep-purple-accent-4"
          class="ml-4 rounded-lg"
          height="10"
        />
      </div>

      <template v-if="cnnResults">
        <!-- Overview cards -->
        <v-row class="my-4">
          <v-col
            v-for="(val, key) in overview"
            :key="key"
            cols="12"
            sm="6"
            md="4"
          >
            <v-card class="pa-3" outlined elevation="0">
              <div class="text-caption text--secondary">
                {{ labels[key] }}
              </div>
              <div
                class="text-h5 font-weight-bold"
                :class="
                  key === 'most_frequent_class'
                    ? 'success--text'
                    : key === 'total_classified'
                    ? 'info--text'
                    : 'warning--text'
                "
              >
                {{ val }}
              </div>
            </v-card>
          </v-col>
        </v-row>

        <v-divider class="my-4"></v-divider>

        <!-- Table -->
        <v-data-table
          :headers="cnnHeaders"
          :items="enhancedTableItems"
          class="packet-table elevation-2"
        >
          <template v-slot:item.class_name="{ item }">
            <div class="d-flex align-center font-weight-bold">
              <v-avatar size="24" color="primary" variant="tonal" class="mr-2">
                <span class="text-caption">
                  {{ item.class_name.charAt(0) }}
                </span>
              </v-avatar>
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
              <span class="text-caption text--secondary"
                >{{ item.percentage }}%</span
              >
            </div>
          </template>

          <template v-slot:item.ips="{ item }">
            <div v-if="item.ips?.length" class="py-2">
              <v-chip
                v-for="(ip, index) in item.ips"
                :key="ip"
                x-small
                color="primary"
                class="mr-1 mb-1 font-weight-bold"
              >
                {{ ip }}
              </v-chip>
            </div>
            <div v-else class="grey--text text-caption font-italic">
              No IPs assigned
            </div>
          </template>
        </v-data-table>

        <RoleDetailsTable
          v-if="cnnResults.ip_role_details"
          :details="cnnResults.ip_role_details"
          class="mt-6"
        />

        <v-divider class="my-4"></v-divider>

        <!-- Pie chart -->
        <PieChart
          v-if="formattedCnnChartData.length"
          :chartData="formattedCnnChartData"
          chartTitle="Rule Based Classification Summary"
        />
      </template>

      <div v-else-if="!cnnLoading" class="text-center pa-4">
        <v-icon size="48" color="grey-lighten-1">mdi-monitor-dashboard</v-icon>
        <p class="text-subtitle-1 text--secondary mt-2">
          Click "Start Rule Based Analysis" to process data.
        </p>
      </div>
    </v-card>

    <!-- Navigation -->
    <div class="d-flex ga-4 mt-4 mx-2">
      <v-btn color="secondary" @click="$emit('prev')" class="control-btn">
        <v-icon start>mdi-arrow-left</v-icon> Previous
      </v-btn>
      <v-btn
        color="primary"
        @click="$emit('next')"
        :disabled="!cnnResults"
        class="control-btn mx-2"
      >
        Continue <v-icon end>mdi-arrow-right</v-icon>
      </v-btn>
    </div>
  </div>
</template>

<script>
import PieChart from "@/components/PieChart.vue";
import RoleDetailsTable from "@/components/RoleDetailsTable.vue";

export default {
  components: { PieChart, RoleDetailsTable },

  props: {
    filename: String,
    cnnLoading: Boolean,
    cnnResults: Object,
    cnnError: String,
    cnnHeaders: Array,
    formattedCnnChartData: Array,
    selectedIps: Array,
  },

  emits: ["prev", "next", "start-analysis"],

  computed: {
    overview() {
      if (!this.cnnResults) return {};
      return {
        most_frequent_class: this.cnnResults.most_frequent_class,
        total_classified: this.cnnResults.total_classified,
        processing_time: this.cnnResults.processing_time?.toFixed(2),
      };
    },
    labels() {
      return {
        most_frequent_class: "Most Frequent Class",
        total_classified: "Total Classified Items",
        processing_time: "Processing Time (s)",
      };
    },
    enhancedTableItems() {
      if (!this.cnnResults?.rule_based_classification_summary) return [];

      const total = this.cnnResults.rule_based_classification_summary.reduce(
        (sum, item) => sum + item.count,
        0
      );

      return this.cnnResults.rule_based_classification_summary.map((item) => ({
        ...item,
        percentage: total > 0 ? ((item.count / total) * 100).toFixed(1) : 0,
      }));
    },
  },

  methods: {
    startAnalysis() {
      this.$emit("start-analysis", { selectedIps: this.selectedIps });
    },
  },
};
</script>
