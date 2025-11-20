<template>
  <v-card class="rounded-xl pa-4" elevation="4">
    <v-card-title class="font-weight-bold">
      Graph Modularity Analysis
    </v-card-title>
    <div ref="chart" style="height: 350px"></div>
    <div class="text-caption mt-4 px-2 grey--text">
      <b>Note:</b> This chart visualizes how the network’s modularity changes as
      the number of clusters increases. Modularity measures the strength of
      community structure: <br /><br />
      • A <b>higher modularity</b> value means clusters are more clearly
      separated.<br />
      • The <b>peak point</b> indicates the optimal number of clusters.<br />
      • The selected value is the cluster count with the highest modularity.
    </div>
  </v-card>
</template>

<script>
import * as echarts from "echarts";

export default {
  name: "ModularityChart",
  props: {
    modularityData: {
      type: Array,
      required: true,
    },
  },
  mounted() {
    this.renderChart();
  },
  watch: {
    modularityData() {
      this.renderChart();
    },
  },
  methods: {
    renderChart() {
      const chart = echarts.init(this.$refs.chart);

      const ks = this.modularityData.map((d) => d.k);
      const scores = this.modularityData.map((d) => d.modularity);

      const option = {
        tooltip: { trigger: "axis" },
        xAxis: {
          type: "category",
          name: "K",
          data: ks,
        },
        yAxis: {
          type: "value",
          name: "Modularity",
        },
        series: [
          {
            type: "line",
            smooth: true,
            symbol: "circle",
            data: scores,
          },
        ],
      };

      chart.setOption(option);
      window.addEventListener("resize", () => chart.resize());
    },
  },
};
</script>

<style scoped></style>
