<template>
  <v-container>
    <p>
      The <strong>Elbow Method</strong> is a technique used to determine the
      optimal number of clusters in a dataset. It works by computing a
      clustering metric, such as the
      <em>Within-Cluster Sum of Squares (WCSS)</em>, for different numbers of
      clusters. As the number of clusters increases, WCSS decreases, because
      points are closer to their cluster centers. The "elbow" point is where the
      reduction in WCSS begins to slow down significantly. This point is
      considered the optimal number of clusters, balancing compactness of
      clusters with simplicity.
    </p>

    <div id="elbow-chart" style="height: 400px"></div>
  </v-container>
</template>

<script>
import * as echarts from "echarts";

export default {
  props: ["elbowData"],
  mounted() {
    this.renderChart();
  },
  methods: {
    renderChart() {
      if (!this.elbowData || !this.elbowData.length) return;

      const dom = document.getElementById("elbow-chart");
      const chart = echarts.init(dom);

      const option = {
        title: { text: "Elbow Method" },
        xAxis: { type: "category", data: this.elbowData.map((d) => d.k) },
        yAxis: { type: "value", name: "WCSS" },
        series: [
          {
            type: "line",
            data: this.elbowData.map((d) => d.wcss),
            smooth: true,
          },
        ],
      };

      chart.setOption(option);
    },
  },
};
</script>
