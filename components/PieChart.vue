<template>
  <v-container>
    <div ref="chartContainer" style="width: 100%; height: 400px"></div>
  </v-container>
</template>

<script>
import * as echarts from "echarts";

export default {
  name: "PieChartEcharts",
  props: {
    // Expect an array of objects: [{ name: 'Class1', value: 10 }, ...]
    chartData: {
      type: Array,
      required: true,
    },
    // Optional chart title
    chartTitle: {
      type: String,
      default: "Pie Chart",
    },
  },
  watch: {
    chartData: {
      handler() {
        this.renderChart();
      },
      deep: true,
    },
  },
  data() {
    return { chart: null };
  },
  mounted() {
    this.renderChart();
    window.addEventListener("resize", this.resizeChart);
  },
  beforeDestroy() {
    window.removeEventListener("resize", this.resizeChart);
    if (this.chart) this.chart.dispose();
    this.chart = null;
  },
  methods: {
    resizeChart() {
      if (this.chart) this.chart.resize();
    },
    renderChart() {
      if (!this.chartData || !this.chartData.length) return;

      // One chart per component: re-renders reuse it.
      if (!this.chart) this.chart = echarts.init(this.$refs.chartContainer);
      const chart = this.chart;

      const option = {
        title: {
          text: this.chartTitle,
          left: "center",
        },
        tooltip: {
          trigger: "item",
          formatter: "{b}: {c} ({d}%)",
        },
        legend: {
          orient: "vertical",
          left: "left",
        },
        series: [
          {
            name: this.chartTitle,
            type: "pie",
            radius: "60%",
            data: this.chartData.map((d) => ({
              value: d.value,
              name: d.name,
            })),
            emphasis: {
              itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: "rgba(0, 0, 0, 0.5)",
              },
            },
          },
        ],
      };

      chart.setOption(option);
    },
  },
};
</script>

<style scoped>
/* Optional: Make the container responsive */
.v-container {
  width: 100%;
}
</style>
