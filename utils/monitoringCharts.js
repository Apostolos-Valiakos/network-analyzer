// ECharts options for the monitoring dashboard, built from Zeek flow rows.
import { formatBytes } from "~/utils/format";

const toInt = (value) => parseInt(value) || 0;

function countBy(stats, keyOf) {
  const counts = {};
  stats.forEach((s) => {
    const key = keyOf(s);
    counts[key] = (counts[key] || 0) + 1;
  });
  return counts;
}

export function trendOption(stats) {
  // ECharts draws line points in array order rather than sorting by x-value,
  // so feed it a chronologically-sorted copy or the line zigzags through time.
  const sorted = [...stats].sort((a, b) => a.ts - b.ts);

  return {
    tooltip: {
      trigger: "axis",
      formatter: (params) => {
        if (!params || !params.length) return "";
        const timeStr = new Date(params[0].value[0]).toLocaleTimeString();
        let tooltip = `<div style="font-weight:bold; margin-bottom:4px;">${timeStr}</div>`;
        params.forEach((p) => {
          tooltip += `${p.marker} ${p.seriesName}: <b>${formatBytes(p.value[1])}</b><br/>`;
        });
        return tooltip;
      },
    },
    legend: { data: ["Bytes Out", "Bytes In"] },
    xAxis: { type: "time", boundaryGap: false },
    yAxis: {
      type: "value",
      axisLabel: { formatter: (val) => formatBytes(val) },
    },
    dataZoom: [
      { type: "inside", xAxisIndex: 0, filterMode: "none" },
      { type: "inside", yAxisIndex: 0, filterMode: "empty" },
    ],
    series: [
      {
        name: "Bytes Out",
        type: "line",
        data: sorted.map((s) => [s.ts * 1000, toInt(s.orig_bytes)]),
        smooth: true,
        itemStyle: { color: "#3b82f6" },
        areaStyle: { opacity: 0.1 },
      },
      {
        name: "Bytes In",
        type: "line",
        data: sorted.map((s) => [s.ts * 1000, toInt(s.resp_bytes)]),
        smooth: true,
        itemStyle: { color: "#10b981" },
        areaStyle: { opacity: 0.1 },
      },
    ],
  };
}

export function stateOption(stats) {
  const counts = countBy(stats, (s) => s.conn_state || "Unknown");
  return {
    tooltip: { trigger: "item" },
    legend: { bottom: "0" },
    series: [
      {
        name: "Connection State",
        type: "pie",
        radius: ["40%", "70%"],
        data: Object.entries(counts).map(([name, value]) => ({ name, value })),
      },
    ],
  };
}

export function protocolOption(stats) {
  const counts = countBy(stats, (s) => s.proto || "unknown");
  return {
    tooltip: { trigger: "item" },
    legend: { bottom: "0" },
    series: [
      {
        name: "Protocol",
        type: "pie",
        radius: "70%",
        data: Object.entries(counts).map(([name, value]) => ({
          name: name.toUpperCase(),
          value,
        })),
      },
    ],
  };
}

export function topTalkersOption(stats) {
  const talkers = {};
  stats.forEach((s) => {
    const ip = s["id.orig_h"];
    if (ip) talkers[ip] = (talkers[ip] || 0) + toInt(s.orig_bytes);
  });
  const top = Object.entries(talkers)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return {
    tooltip: {
      trigger: "axis",
      formatter: (params) => `${params[0].name}: ${formatBytes(params[0].value)}`,
    },
    xAxis: { type: "value", show: false },
    yAxis: { type: "category", data: top.map((i) => i[0]).reverse() },
    series: [
      {
        data: top.map((i) => i[1]).reverse(),
        type: "bar",
        itemStyle: { color: "#8b5cf6", borderRadius: [0, 5, 5, 0] },
      },
    ],
  };
}

export function conversationsOption(stats) {
  const linksById = new Map();
  stats.forEach((s) => {
    const src = s["id.orig_h"];
    const dst = s["id.resp_h"];
    if (!src || !dst) return;
    const id = `${src}-${dst}`;
    if (!linksById.has(id)) linksById.set(id, { source: src, target: dst, bytes: 0 });
    linksById.get(id).bytes += toInt(s.orig_bytes) + toInt(s.resp_bytes);
  });

  const busiest = Array.from(linksById.values())
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 50);
  const activeNodes = new Set();
  busiest.forEach((l) => {
    activeNodes.add(l.source);
    activeNodes.add(l.target);
  });

  return {
    tooltip: { trigger: "item" },
    series: [
      {
        type: "graph",
        layout: "force",
        data: Array.from(activeNodes).map((ip) => ({
          name: ip,
          symbolSize: 22,
          itemStyle: { color: "#3b82f6" },
          label: { show: true },
        })),
        links: busiest.map((l) => ({
          source: l.source,
          target: l.target,
          lineStyle: { width: Math.min(Math.max(l.bytes / 5000, 1), 6) },
        })),
        roam: true,
        force: { repulsion: 150, edgeLength: 80 },
      },
    ],
  };
}
