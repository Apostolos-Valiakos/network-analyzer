<template>
  <v-row>
    <v-col cols="12">
      <v-card class="elevation-4 rounded-xl pa-4">
        <h3 class="text-h6 mb-4">Traffic Trend (Bytes over Time)</h3>
        <EChart chart-id="trend-chart" :height="350" :option="trend" />
      </v-card>
    </v-col>
    <v-col cols="12">
      <v-card class="elevation-4 rounded-xl pa-4">
        <h3 class="text-h6 mb-4">Network Conversations (Topology)</h3>
        <EChart chart-id="conversations-chart" :height="450" :option="conversations" replace />
      </v-card>
    </v-col>
    <v-col cols="12" md="4">
      <v-card class="elevation-4 rounded-xl pa-4">
        <h3 class="text-h6 mb-4">Protocol Distribution</h3>
        <EChart chart-id="protocol-chart" :height="300" :option="protocols" />
      </v-card>
    </v-col>
    <v-col cols="12" md="4">
      <v-card class="elevation-4 rounded-xl pa-4">
        <h3 class="text-h6 mb-4">Connection States</h3>
        <EChart chart-id="state-chart" :height="300" :option="states" />
      </v-card>
    </v-col>
    <v-col cols="12" md="4">
      <v-card class="elevation-4 rounded-xl pa-4">
        <h3 class="text-h6 mb-4">Top Talkers (Bytes Out)</h3>
        <EChart chart-id="top-talkers-chart" :height="300" :option="topTalkers" />
      </v-card>
    </v-col>
  </v-row>
</template>

<script>
import EChart from "@/components/monitoring/EChart.vue";
import {
  conversationsOption,
  protocolOption,
  stateOption,
  topTalkersOption,
  trendOption,
} from "@/utils/monitoringCharts";

const TOPOLOGY_REFRESH_MS = 60000;

export default {
  name: "MonitoringCharts",
  components: { EChart },
  props: {
    stats: { type: Array, required: true },
    live: { type: Boolean, default: false },
  },
  data() {
    return {
      // The force layout restarts on every update, so unlike the other charts
      // the topology refreshes on a timer rather than with every live batch.
      conversations: conversationsOption(this.stats),
    };
  },
  computed: {
    trend() {
      return trendOption(this.stats);
    },
    protocols() {
      return protocolOption(this.stats);
    },
    states() {
      return stateOption(this.stats);
    },
    topTalkers() {
      return topTalkersOption(this.stats);
    },
  },
  mounted() {
    this.topologyTimer = setInterval(() => {
      if (this.live && this.stats.length > 0) {
        this.conversations = conversationsOption(this.stats);
      }
    }, TOPOLOGY_REFRESH_MS);
  },
  beforeDestroy() {
    clearInterval(this.topologyTimer);
  },
};
</script>
