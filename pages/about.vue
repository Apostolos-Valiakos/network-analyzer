<template>
  <v-container class="page-container">
    <!-- Hero -->
    <v-card class="themed-card pa-8 mb-6">
      <div
        class="d-flex align-start align-sm-center flex-column flex-sm-row mb-6"
      >
        <v-img
          src="/6g_logo.png"
          alt="Logo"
          contain
          max-width="72"
          class="mb-4 mb-sm-0 mr-sm-6 flex-grow-0"
        />
        <div>
          <h1 class="text-h4 text-md-h3 font-weight-black primary--text mb-1">
            Network Analyzer
          </h1>
          <p class="text-subtitle-1 text-fade mb-0">
            5G / 6G Network Traffic Analysis &amp; Intelligence Platform
          </p>
        </div>
      </div>

      <p class="body-1 text-fade mb-4">
        An open-source research platform developed at the
        <strong class="primary--text">University of Thessaly</strong> for deep
        inspection and classification of 5G and 6G network traffic. The system
        ingests raw PCAP captures or a live
        <strong class="primary--text">Zeek</strong> telemetry stream, applies
        unsupervised machine-learning clustering and rule-based role assessment,
        and delivers interactive dashboards for researchers, security analysts,
        and network engineers.
      </p>

      <v-btn
        small
        outlined
        color="primary"
        :href="apiDocsUrl"
        target="_blank"
        rel="noopener noreferrer"
      >
        <v-icon left small>mdi-book-open-variant</v-icon>
        Browse API Documentation
      </v-btn>
    </v-card>

    <!-- Core Capabilities -->
    <v-card class="themed-card pa-6 mb-6">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-rocket-launch-outline</v-icon>
        Core Capabilities
      </h2>

      <v-expansion-panels flat multiple>
        <v-expansion-panel
          v-for="(cap, i) in capabilities"
          :key="i"
          class="themed-panel mb-2"
        >
          <v-expansion-panel-header class="font-weight-medium text-subtitle-1">
            <div>
              <v-icon left color="primary" small>{{ cap.icon }}</v-icon>
              {{ cap.title }}
            </div>
          </v-expansion-panel-header>
          <v-expansion-panel-content class="pa-4 body-2 text-fade">
            <p>{{ cap.description }}</p>
            <v-list
              v-if="cap.subpoints"
              dense
              style="background: transparent !important"
            >
              <v-list-item v-for="(s, j) in cap.subpoints" :key="j">
                <v-list-item-icon class="mr-2">
                  <v-icon small color="primary">mdi-circle-small</v-icon>
                </v-list-item-icon>
                <v-list-item-content>
                  <v-list-item-title style="text-wrap: pretty" class="body-2">
                    {{ s }}
                  </v-list-item-title>
                </v-list-item-content>
              </v-list-item>
            </v-list>
          </v-expansion-panel-content>
        </v-expansion-panel>
      </v-expansion-panels>
    </v-card>

    <!-- Architecture -->
    <v-card class="themed-accent-card pa-6 mb-6">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-sitemap</v-icon>
        System Architecture
      </h2>
      <p class="body-2 text-fade mb-4">
        Three tiers communicate over REST and WebSocket. An optional host sensor
        VM feeds live Zeek flow data and on-demand PCAP snapshots into the
        monitoring pipeline using a shared internal token.
      </p>
      <pre class="arch-diagram text-caption text-fade">
┌────────────────────────────────────────────────────────────┐
│              Browser  (Nuxt 2 / Vue 2 SPA)                 │
│  Analyze · Clustering · Real Time · Monitoring · Admin     │
└─────────────────────────┬──────────────────────────────────┘
                          │  REST + WebSocket (Socket.IO)
┌─────────────────────────▼──────────────────────────────────┐
│          Flask API  (server/app.py)   :5555                │
│  JWT auth · SocketIO · Swagger UI (/apidocs, public)       │
│  PCAP analysis · Clustering · Role pipeline · Zeek ingest  │
└───────────┬────────────────────────────┬───────────────────┘
            │ SQLAlchemy ORM             │ psycopg2 bulk insert
┌───────────▼────────────────────────────▼───────────────────┐
│         PostgreSQL 14 + TimescaleDB                        │
│  users · pcap_files · flow_statistics (hypertable)         │
│  role_snapshots · ue_sessions · cluster_results            │
└─────────────────────────▲──────────────────────────────────┘
                          │  X-Internal-Token
┌─────────────────────────┴──────────────────────────────────┐
│       Host Sensor VM  (Host Files/)   :5005                │
│  zeek_agent.py  →  POST /v1/ingest/zeek                    │
│  start_sensor.sh — tcpdump capture + Nmap async service    │
└────────────────────────────────────────────────────────────┘
</pre
      >
    </v-card>

    <!-- Tech Stack -->
    <v-card class="themed-card pa-8 mb-6">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-code-braces</v-icon>
        Technology Stack
      </h2>

      <v-simple-table class="themed-table rounded-lg">
        <template v-slot:default>
          <thead>
            <tr>
              <th
                class="text-left font-weight-bold primary--text text-uppercase"
              >
                Layer
              </th>
              <th
                class="text-left font-weight-bold primary--text text-uppercase"
              >
                Component
              </th>
              <th
                class="text-left font-weight-bold primary--text text-uppercase"
              >
                Technologies
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in techStack" :key="item.layer + item.component">
              <td class="font-weight-medium">{{ item.layer }}</td>
              <td class="text-fade">{{ item.component }}</td>
              <td>
                <span class="font-mono primary--text">{{
                  item.technologies
                }}</span>
              </td>
            </tr>
          </tbody>
        </template>
      </v-simple-table>
    </v-card>

    <!-- API Documentation -->
    <v-card class="themed-accent-card pa-6 mb-6">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-api</v-icon>
        API Documentation
      </h2>
      <p class="body-1 text-fade mb-4">
        An interactive Swagger UI is served directly by the Flask backend at
        <code class="primary--text">/apidocs</code>. It documents every endpoint
        — parameters, request bodies, response schemas, and authentication
        requirements — and requires no login to browse. Endpoints that require a
        JWT Bearer token are marked with a lock icon; use the
        <strong class="primary--text">Authorize</strong>
        button in the UI to supply your token for live testing.
      </p>
      <v-btn
        outlined
        color="primary"
        :href="apiDocsUrl"
        target="_blank"
        rel="noopener noreferrer"
      >
        <v-icon left>mdi-open-in-new</v-icon>
        Open Swagger UI
      </v-btn>
    </v-card>

    <!-- License -->
    <v-card class="themed-card pa-8">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-license</v-icon>
        License &amp; Credits
      </h2>
      <p class="body-1 text-fade mb-4">
        Developed by the
        <strong class="primary--text">University of Thessaly</strong> as part of
        ongoing research into next-generation mobile network intelligence and
        traffic analysis.
      </p>
      <v-list dense style="background: transparent !important">
        <v-list-item>
          <v-list-item-icon class="mr-3">
            <v-icon color="primary">mdi-copyright</v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title class="body-1">
              <span class="font-weight-medium">Copyright:</span>
              &copy; 2025 University of Thessaly
            </v-list-item-title>
          </v-list-item-content>
        </v-list-item>
        <v-list-item>
          <v-list-item-icon class="mr-3">
            <v-icon color="primary">mdi-file-document-outline</v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title class="body-1">
              <span class="font-weight-medium">License:</span> MIT License
            </v-list-item-title>
          </v-list-item-content>
        </v-list-item>
      </v-list>
    </v-card>
  </v-container>
</template>

<script>
export default {
  name: "About",

  computed: {
    apiDocsUrl() {
      return (
        (process.env.VUE_APP_API_BASE_URL || "http://127.0.0.1:5555") +
        "/apidocs"
      );
    },
  },

  data: () => ({
    capabilities: [
      {
        icon: "mdi-file-chart-outline",
        title: "PCAP Upload & Analysis",
        description:
          "Upload any PCAP file and receive a full breakdown within seconds:",
        subpoints: [
          "Protocol distribution — visualise TCP, UDP, GTP, SCTP, ICMP and their relative prevalence.",
          "Conversation statistics — quantify traffic volume between every observed IP pair.",
          "Interactive network graph — nodes represent IP addresses; edge weight reflects traffic volume and packet count.",
        ],
      },
      {
        icon: "mdi-graph",
        title: "Agglomerative Clustering & Anomaly Detection",
        description:
          "Unsupervised hierarchical clustering groups IP endpoints by traffic behaviour:",
        subpoints: [
          "Modularity-based automatic k-selection — graph-theoretic modularity scores suggest the optimal number of clusters so you do not have to guess.",
          "Cluster hierarchy dendrogram — visualise how groups merge at each agglomerative linkage step.",
          "Anomaly flagging — outlier IPs that deviate significantly from every cluster are highlighted as potential threats or misconfigurations.",
        ],
      },
      {
        icon: "mdi-account-search-outline",
        title: "IP Role Assessment",
        description:
          "A rule-based classification engine assigns a functional role to every observed IP address — 5G Core NF, O-RAN component, User Equipment, external server, or unknown. The full report is exportable as JSON or CSV for downstream tooling.",
      },
      {
        icon: "mdi-cellphone-wireless",
        title: "UE Session Tracking",
        description:
          "Extracts and correlates User Equipment sessions from 4G/5G control-plane traffic, linking IMSI, GUTI, and assigned IPv4 addresses for per-device behaviour analysis — essential for mobile network forensics.",
      },
      {
        icon: "mdi-monitor-dashboard",
        title: "Continuous Real-Time Monitoring",
        description:
          "A lightweight Zeek agent on the sensor VM streams parsed connection logs to the API server in real time:",
        subpoints: [
          "Live flow table — sortable, filterable view of active and recent connections stored in a TimescaleDB hypertable.",
          "Anomaly alerts — WebSocket-pushed notifications for massive data transfers (> 5 MB), packet floods (> 5 000 pkts), and rejected connections.",
          "Nmap scan integration — trigger on-demand network scans from the dashboard and retrieve structured results.",
          "Time-range export — download flow statistics as CSV or JSON for any historical window.",
        ],
      },
      {
        icon: "mdi-cloud-upload-outline",
        title: "Streaming PCAP Assembly",
        description:
          "Accepts chunked Base64-encoded packet data from an external source (e.g. a live sniffer or remote capture agent) and assembles it server-side into a coherent PCAP file, enabling fully automated remote capture-and-analyse workflows.",
      },
    ],

    techStack: [
      {
        layer: "Frontend",
        component: "SPA framework",
        technologies: "Nuxt 2, Vue 2, Vuetify 2",
      },
      {
        layer: "Frontend",
        component: "Charts & graphs",
        technologies: "Apache ECharts, vue-echarts",
      },
      {
        layer: "Frontend",
        component: "Real-time client",
        technologies: "Socket.IO client",
      },
      {
        layer: "Backend",
        component: "API server",
        technologies: "Flask, Flask-SocketIO, Flask-JWT-Extended",
      },
      {
        layer: "Backend",
        component: "API documentation",
        technologies: "Flasgger (Swagger 2.0 UI)",
      },
      {
        layer: "Backend",
        component: "Rate limiting",
        technologies: "Flask-Limiter",
      },
      {
        layer: "Backend",
        component: "Packet analysis",
        technologies: "Scapy, PyShark / tshark, pandas",
      },
      {
        layer: "Backend",
        component: "Clustering & ML",
        technologies: "scikit-learn, NetworkX, python-louvain",
      },
      {
        layer: "Database",
        component: "Relational store",
        technologies: "PostgreSQL 14, SQLAlchemy",
      },
      {
        layer: "Database",
        component: "Time-series flows",
        technologies: "TimescaleDB (hypertable on flow_statistics)",
      },
      {
        layer: "Sensor VM",
        component: "Flow telemetry",
        technologies: "Zeek IDS, zeek_agent.py",
      },
      {
        layer: "Sensor VM",
        component: "Packet capture",
        technologies: "tcpdump, Nmap",
      },
    ],
  }),
};
</script>

<style scoped>
.page-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.themed-card {
  background-color: var(--surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: 16px !important;
}

.themed-accent-card {
  background-color: var(--surface) !important;
  border: 1px solid var(--accent-border) !important;
  border-radius: 16px !important;
}

.themed-panel {
  background-color: var(--surface-alt) !important;
  border: 1px solid var(--border) !important;
  border-radius: 12px !important;
  box-shadow: none !important;
  overflow: hidden;
}

.themed-table {
  background-color: var(--surface-alt) !important;
  border: 1px solid var(--border) !important;
  overflow: hidden;
}

.themed-table th {
  background-color: var(--highlight-bg) !important;
  border-bottom: 1px solid var(--border) !important;
}

.themed-table td {
  border-bottom: 1px solid var(--border) !important;
}

.arch-diagram {
  display: block;
  overflow-x: auto;
  background: var(--highlight-bg);
  border: 1px solid var(--accent-border);
  border-radius: 8px;
  padding: 16px;
  font-family: "SF Mono", "Monaco", "Inconsolata", "Roboto Mono", monospace;
  line-height: 1.5;
  white-space: pre;
}

.font-mono {
  font-family: monospace;
}
</style>
