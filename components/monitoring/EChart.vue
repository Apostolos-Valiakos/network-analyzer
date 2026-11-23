<template>
  <div :id="chartId" :style="{ height: height + 'px' }"></div>
</template>

<script>
import * as echarts from "echarts";

// One ECharts chart. It lives exactly as long as this component, so a chart can
// never keep drawing into an element that Vue has removed.
export default {
  name: "EChart",
  props: {
    chartId: { type: String, required: true },
    height: { type: Number, required: true },
    option: { type: Object, required: true },
    // Replace the previous option instead of merging into it
    replace: { type: Boolean, default: false },
  },
  watch: {
    option() {
      this.draw();
    },
  },
  mounted() {
    // Not in data(): Vue must not make the chart object reactive.
    this.chart = echarts.init(this.$el);
    this.draw();
    window.addEventListener("resize", this.resize);
  },
  beforeDestroy() {
    window.removeEventListener("resize", this.resize);
    this.chart.dispose();
  },
  methods: {
    draw() {
      this.chart.setOption(this.option, this.replace);
    },
    resize() {
      this.chart.resize();
    },
  },
};
</script>
