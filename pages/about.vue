<template>
  <v-container class="futuristic-light-container">
    <v-card class="data-card pa-8 mb-6">
      <h1 class="text-h4 text-md-h3 font-weight-black mb-4 primary--text">
        Network Traffic Analysis & Clustering
      </h1>
      <p class="text-subtitle-1 grey--text text--darken-2 mb-6">
        Welcome to the cutting-edge front-end interface for the
        <strong class="primary--text text--darken-1"
          >Network Traffic Analysis and PCAP Generation Service
        </strong>
        a powerful toolkit developed by the
        <strong class="primary--text text--darken-1"
          >University of Thessaly</strong
        >
        for deep network forensics and intelligence.
      </p>
      <p class="body-1">
        Our platform transforms raw network data (PCAP files) into actionable
        insights, utilizing a sophisticated blend of data science and advanced
        network protocol analysis.
      </p>
    </v-card>

    <v-row class="mb-6">
      <v-col cols="12">
        <v-card class="status-card pa-6">
          <h2 class="text-h5 font-weight-bold mb-4 primary--text">
            <v-icon color="primary" class="mr-2">mdi-cogs</v-icon>
            Core Mission: Data to Insight
          </h2>

          <div class="realtime-view pa-4 mb-4">
            <v-icon large color="blue darken-2" class="mb-2">
              mdi-lightbulb-on-outline</v-icon
            >
            <p class="font-weight-medium text-body-1 text--primary">
              Our goal is to provide researchers, security analysts, and network
              engineers with the tools to efficiently:
            </p>
          </div>

          <v-expansion-panels
            flat
            multiple
            class="transparent-expansion-panels mission-panels"
          >
            <v-expansion-panel class="mb-2 data-card">
              <v-expansion-panel-header
                class="font-weight-medium text-subtitle-1 grey--text text--darken-3"
              >
                Deconstruct Network Traffic
              </v-expansion-panel-header>
              <v-expansion-panel-content
                class="pa-4 body-2 grey--text text--darken-1"
              >
                Move beyond simple packet counting to understand true network
                behavior.
              </v-expansion-panel-content>
            </v-expansion-panel>

            <v-expansion-panel class="mb-2 data-card">
              <v-expansion-panel-header
                class="font-weight-medium text-subtitle-1 grey--text text--darken-3"
              >
                Identify Key Entities
              </v-expansion-panel-header>
              <v-expansion-panel-content
                class="pa-4 body-2 grey--text text--darken-1"
              >
                Automatically classify and track user equipment (UE) sessions
                and assign logical roles to IP addresses (e.g., 5G core, UE,
                Network Functions).
              </v-expansion-panel-content>
            </v-expansion-panel>

            <v-expansion-panel class="mb-2 data-card">
              <v-expansion-panel-header
                class="font-weight-medium text-subtitle-1 grey--text text--darken-3"
              >
                Reveal Hidden Patterns
              </v-expansion-panel-header>
              <v-expansion-panel-content
                class="pa-4 body-2 grey--text text--darken-1"
              >
                Employ unsupervised learning (clustering) to group similar
                network behaviors, making it easy to spot anomalies or emerging
                trends.
              </v-expansion-panel-content>
            </v-expansion-panel>

            <v-expansion-panel class="mb-2 data-card">
              <v-expansion-panel-header
                class="font-weight-medium text-subtitle-1 grey--text text--darken-3"
              >
                Enable Dynamic Research
              </v-expansion-panel-header>
              <v-expansion-panel-content
                class="pa-4 body-2 grey--text text--darken-1"
              >
                Offer the flexibility to generate and analyze custom PCAP files
                on demand or from live capture streams.
              </v-expansion-panel-content>
            </v-expansion-panel>
          </v-expansion-panels>
        </v-card>
      </v-col>
    </v-row>

    <v-card class="data-card pa-8 mb-6">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-rocket-launch</v-icon>
        Key Platform Capabilities
      </h2>

      <v-expansion-panels flat multiple class="transparent-expansion-panels">
        <v-expansion-panel
          v-for="(capability, i) in capabilities"
          :key="i"
          class="mb-2 data-card"
        >
          <v-expansion-panel-header
            class="font-weight-medium text-subtitle-1 grey--text text--darken-3"
          >
            <div>
              <v-icon left color="blue-grey lighten-1">
                {{ capability.icon }}
              </v-icon>
              {{ capability.title }}
            </div>
          </v-expansion-panel-header>
          <v-expansion-panel-content
            class="pa-4 body-2 grey--text text--darken-1"
          >
            <p>{{ capability.description }}</p>
            <v-list
              dense
              class="transparent-list-nested"
              v-if="capability.subpoints"
            >
              <v-list-item v-for="(sub, j) in capability.subpoints" :key="j">
                <v-list-item-icon class="mr-2">
                  <v-icon small color="blue-grey lighten-2"
                    >mdi-circle-small</v-icon
                  >
                </v-list-item-icon>
                <v-list-item-content>
                  <v-list-item-title style="text-wrap: pretty" class="body-2">
                    {{ sub }}
                  </v-list-item-title>
                </v-list-item-content>
              </v-list-item>
            </v-list>
          </v-expansion-panel-content>
        </v-expansion-panel>
      </v-expansion-panels>
    </v-card>

    <v-card class="data-card pa-8 mb-6">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-code-braces</v-icon>
        Technology Stack
      </h2>
      <p class="body-1 mb-4">
        This front-end is powered by a robust
        <strong class="primary--text">Flask API</strong> backend developed in
        Python by the
        <strong class="primary--text">University of Thessaly</strong>.
      </p>

      <v-simple-table class="data-card transparent-table">
        <template v-slot:default>
          <thead>
            <tr>
              <th
                class="text-left text-uppercase font-weight-bold primary--text text--darken-1"
              >
                Component
              </th>
              <th
                class="text-left text-uppercase font-weight-bold primary--text text--darken-1"
              >
                Function
              </th>
              <th
                class="text-left text-uppercase font-weight-bold primary--text text--darken-1"
              >
                Technologies Used
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in techStack" :key="item.component">
              <td>
                <span class="font-weight-medium">{{ item.component }}</span>
              </td>
              <td>{{ item.function }}</td>
              <td>
                <span class="font-mono primary--text text--darken-1">{{
                  item.technologies
                }}</span>
              </td>
            </tr>
          </tbody>
        </template>
      </v-simple-table>
    </v-card>

    <v-card class="status-card pa-8">
      <h2 class="text-h5 font-weight-bold mb-4 primary--text">
        <v-icon color="primary" class="mr-2">mdi-license</v-icon>
        License and Credits
      </h2>
      <p class="body-1 mb-2">
        This project is a product of research and development at the
        <strong class="primary--text">University of Thessaly</strong>.
      </p>
      <v-list dense class="transparent-list">
        <v-list-item>
          <v-list-item-icon class="mr-3">
            <v-icon color="primary">mdi-copyright</v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title class="body-1">
              <span class="font-weight-medium">Copyright:</span> (c) 2025 by
              University of Thessaly.
            </v-list-item-title>
          </v-list-item-content>
        </v-list-item>
        <v-list-item>
          <v-list-item-icon class="mr-3">
            <v-icon color="primary">mdi-file-document-outline</v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title class="body-1">
              <span class="font-weight-medium">License:</span> MIT License.
            </v-list-item-title>
          </v-list-item-content>
        </v-list-item>
      </v-list>
    </v-card>
  </v-container>
</template>

<script>
export default {
  name: "AboutUs",
  data: () => ({
    capabilities: [
      {
        icon: "mdi-file-chart-outline",
        title: "Advanced PCAP Analysis",
        description:
          "Upload any PCAP file and immediately receive a detailed breakdown of its contents:",
        subpoints: [
          "Conversation Statistics: Quantify traffic flow between specific IP pairs.",
          "Protocol Distribution: Visualize the mix of protocols (TCP, UDP, ICMP, etc.) and their prevalence.",
          "Network Graph Generation: View conversations as a dynamic graph, where nodes are IPs and links represent traffic volume.",
        ],
      },
      {
        icon: "mdi-account-search-outline",
        title: "Intelligent IP Role Assessment",
        description:
          "We use a rule-based algorithm to classify the function of every observed IP address, giving context to your network map. This process helps rapidly differentiate between standard infrastructure (5G core, O-RAN components) and end-user devices.",
      },
      {
        icon: "mdi-cellphone-wireless",
        title: "User Equipment (UE) Session Tracking",
        description:
          "Specifically designed for mobile and telecom network analysis, this module extracts and tracks sessions belonging to individual User Equipment, crucial for identifying device-specific behavior and troubleshooting.",
      },
      {
        icon: "mdi-graph",
        title: "Agglomerative Clustering & Anomaly Detection",
        description:
          "Our platform uses advanced agglomerative clustering to group IP entities based on their traffic patterns and features.",
        subpoints: [
          "Behavioral Segmentation: Automatically identify clusters of similar devices or services.",
          "Modularity-Based Suggestion: We incorporate graph theory principles (Modularity) to suggest the optimal number of clusters (k), maximizing the coherence of the detected groups.",
          "Anomaly Flagging: Quickly identify outlier IPs that don't fit into established clusters, pointing directly to potential security incidents or misconfigurations.",
        ],
      },
      {
        icon: "mdi-cloud-upload-outline",
        title: "Dynamic PCAP Generation & Streaming",
        description:
          "We support experimental and research workflows by allowing:",
        subpoints: [
          "PCAP Assembly: Stream Base64-encoded raw packet chunks from an external source (like a live sniffer) and assemble them on the server into a cohesive PCAP file.",
          "Automated Pipeline (WebSocket): Initiate a long-running packet capture from a specified WebSocket URL for a set duration, then automatically run the full analysis pipeline on the resulting PCAP.",
        ],
      },
    ],
    techStack: [
      {
        component: "Data Handling",
        function: "Packet manipulation and PCAP file processing.",
        technologies: "Scapy, pandas",
      },
      {
        component: "Web Server",
        function: "Core API for processing requests and serving data.",
        technologies: "Flask, Flask-CORS",
      },
      {
        component: "Documentation",
        function: "Interactive API documentation for developers.",
        technologies: "Flasgger (Swagger UI)",
      },
    ],
  }),
};
</script>

<style scoped>
/* The provided futuristic-light-container and other styles should be here */
.futuristic-light-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
  background-color: #f0f4f8;
  font-family: "Inter", sans-serif;
  border-radius: 20px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.05);
}

.realtime-view {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: 24px;
  padding: 16px;
  border: 1px dashed #3b82f644;
  border-radius: 16px;
}

.status-card {
  border: 1px solid #d1e5ff;
  background-color: #f7faff !important;
  border-radius: 16px;
  box-shadow: 0 4px 12px rgba(59, 130, 246, 0.05);
}

.data-card {
  border: 1px solid #e2e8f0;
  background-color: white !important;
  border-radius: 16px;
}

.controls-section {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
}

.control-btn {
  border-radius: 16px !important;
  font-weight: 700;
  text-transform: none;
  letter-spacing: 0.5px;
}

.metric-box {
  background-color: #f7faff;
  border: 1px solid #e0f2fe;
  padding: 12px;
  border-radius: 12px;
  margin-bottom: 8px;
}

.metric-label {
  font-size: 0.8rem;
  color: #64748b;
  font-weight: 500;
  margin-bottom: 4px;
}

.metric-value {
  font-size: 1.5rem;
  font-weight: 800;
  color: #1e40af;
}

.packet-list {
  background-color: #f7faff;
  border-radius: 12px;
  padding: 8px;
}

.packet-item {
  border-bottom: 1px solid #e0f2fe;
  padding: 8px 0;
}
.packet-item:last-child {
  border-bottom: none;
}
.font-mono {
  font-family: monospace;
}

/* Additional styles for this component to match the theme */
.primary--text {
  color: #1e40af !important; /* Ensure primary color fits the theme */
}

.transparent-list {
  background-color: transparent !important;
}
.transparent-list-nested {
  background-color: transparent !important;
  padding-left: 16px !important;
}

.transparent-expansion-panels .v-expansion-panel {
  background-color: white !important; /* Match data-card background */
  border: 1px solid #e2e8f0; /* Match data-card border */
  border-radius: 16px;
  box-shadow: none; /* Remove default shadow */
  overflow: hidden; /* Ensure border-radius is applied */
}

.transparent-expansion-panels .v-expansion-panel-header {
  padding: 16px;
  min-height: 56px;
}

.transparent-expansion-panels .v-expansion-panel-content__wrap {
  padding: 0 16px 16px 16px;
}

.transparent-table {
  background-color: white !important; /* Match data-card */
  border: 1px solid #e2e8f0;
  border-radius: 16px;
  overflow: hidden; /* For rounded corners */
}

.transparent-table th,
.transparent-table td {
  border-bottom: 1px solid #f0f4f8 !important; /* Lighter divider */
}

.transparent-table thead th {
  background-color: #f7faff !important; /* Light header background */
}
</style>
