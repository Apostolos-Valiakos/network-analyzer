<template>
  <div>
    <v-card class="pa-6 mb-8 rounded-xl connection-card">
      <h3 class="text-h6 font-weight-bold mb-4 text-primary">
        <v-icon color="primary" class="mr-2">mdi-brain</v-icon>
        Rule Based Analysis
      </h3>

      <v-alert v-if="cnnError" type="error" class="mb-4" variant="tonal">
        {{ cnnError }}
      </v-alert>

      <div class="d-flex align-center mb-4">
        <v-btn
          color="primary"
          size="large"
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
            <v-card class="pa-3" variant="outlined" elevation="0">
              <div class="text-caption text-medium-emphasis">
                {{ labels[key] }}
              </div>
              <div
                class="text-h5 font-weight-bold"
                :class="
                  key === 'most_frequent_class'
                    ? 'text-success'
                    : key === 'total_classified'
                    ? 'text-info'
                    : 'text-warning'
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
          :items="cnnResults.rule_based_classification_summary"
          class="packet-table elevation-2"
          density="compact"
        >
          <template v-slot:item.ips="{ item }">
            <ul v-if="item.ips?.length">
              <li v-for="ip in item.ips" :key="ip">{{ ip }}</li>
            </ul>
            <div v-else>—</div>
          </template>
        </v-data-table>

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
        <p class="text-subtitle-1 text-medium-emphasis mt-2">
          Click "Start Rule Based Analysis" to process data.
        </p>
      </div>
    </v-card>

    <!-- Navigation -->
    <div class="d-flex ga-4 mt-4">
      <v-btn color="secondary" @click="$emit('prev')" class="control-btn">
        <v-icon start>mdi-arrow-left</v-icon> Previous
      </v-btn>
      <v-btn
        color="primary"
        @click="$emit('next')"
        :disabled="!cnnResults"
        class="control-btn"
      >
        Continue <v-icon end>mdi-arrow-right</v-icon>
      </v-btn>
    </div>
  </div>
</template>

<script>
import PieChart from "@/components/PieChart.vue";

export default {
  components: { PieChart },

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
  },

  methods: {
    startAnalysis() {
      this.$emit("start-analysis", { selectedIps: this.selectedIps });
    },
  },
};
</script>
