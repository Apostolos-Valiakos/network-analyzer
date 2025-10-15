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
  mounted() {
    this.renderChart();
  },
  methods: {
    renderChart() {
      if (!this.chartData || !this.chartData.length) return;

      const chartDom = this.$refs.chartContainer;
      const chart = echarts.init(chartDom);

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

      // Resize chart when window resizes
      window.addEventListener("resize", () => {
        chart.resize();
      });
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
