<!-- Στο hover να φαίνονται τα πρωτοκολα και πόσα μηνύματα στέλνονται -->
<template>
  <v-container
    v-if="graphData"
    id="chart-container"
    class="pa-4"
    style="height: 600px"
  ></v-container>
</template>

<script>
import * as echarts from "echarts";

export default {
  name: "NetworkGraph",
  props: {
    graphData: Object,
    edgeLength: {
      type: Number,
      default: 10,
    },
  },
  mounted() {
    this.initChart();
    window.addEventListener("resize", this.resizeChart);
  },
  unmounted() {
    window.removeEventListener("resize", this.resizeChart);
    if (this.chart) this.chart.dispose();
  },
  methods: {
    initChart() {
      if (
        !this.graphData ||
        !this.graphData.nodes ||
        !this.graphData.links ||
        !this.graphData.categories
      ) {
        console.error("Invalid graph data");
        return;
      }

      const dom = document.getElementById("chart-container");
      this.chart = echarts.init(dom);
      const categoryNames = this.graphData.categories.map((cat) => cat.name);

      const option = {
        tooltip: {},
        legend: {
          show: true,
          data: categoryNames,
          top: "top",
          left: "center",
          orient: "horizontal",
        },
        series: [
          {
            type: "graph",
            layout: "force",
            animation: false,
            label: {
              position: "top",
              formatter: "{b}",
              show: true,
            },
            draggable: true,
            roam: true,
            zoom: 5,
            categories: this.graphData.categories,
            data: this.graphData.nodes.map((node, idx) => ({
              ...node,
              id: idx,
            })),
            force: {
              edgeLength: this.edgeLength,
              repulsion: 20,
              gravity: 0.3,
            },
            edges: this.graphData.links,
          },
        ],
      };

      this.chart.setOption(option);
    },
    resizeChart() {
      if (this.chart) {
        this.chart.resize();
      }
    },
  },
};
</script>

<style scoped>
#chart-container {
  width: 100%;
}
</style>
