<template>
  <v-container class="pa-4">
    <div>
      <h1 class="text-h5 mb-4">
        Select a network traffic file to analyze in PCAP format
      </h1>

      <h5 class="text-disabled mb-2 grey--text">
        The .pcap file you upload for analysis is saved and stored in our
        server.
      </h5>
    </div>

    <v-file-input
      v-model="file"
      label="Select a .pcap file to analyze"
      filled
      prepend-icon="mdi-file"
      show-size
      accept=".pcap"
      @change="handleFile"
    ></v-file-input>

    <v-btn
      :disabled="!file"
      :loading="loading"
      color="primary"
      class="mt-4"
      @click="sendFile"
    >
      Send
    </v-btn>
    <v-btn
      v-if="showUEButon"
      color="secondary"
      class="mt-4"
      @click="downloadConversations"
    >
      Vizualize Network
    </v-btn>
    <NetworkGraph v-if="graphData" :graphData="graphData" />

    <div v-if="analysis" class="mt-4">
      <h3>Total Packets: {{ analysis.total_packets }}</h3>

      <h4 class="mt-6 mb-2">IP Protocols</h4>
      <v-data-table
        :headers="ipProtocolHeaders"
        :items="ipProtocolItems"
        class="elevation-1"
        dense
        disable-pagination
        hide-default-footer
        show-expand
        item-key="ip"
        :expanded.sync="expanded"
      >
        <template #item.protocols="{ item }">
          {{ item.protocols[0] }}
        </template>

        <template #expanded-item="{ item }">
          <td :colspan="ipProtocolHeaders.length">
            <div class="mt-4">
              <!-- Customize with the data you want to show -->
              <p><b>Full Protocol List: </b>{{ item.protocols.join(", ") }}</p>
            </div>
          </td>
        </template>
      </v-data-table>
    </div>
    <v-btn
      v-if="showUEButon"
      :disabled="!file"
      color="primary"
      class="mt-4"
      @click="getUeInfo"
    >
      Get UE Sessions
    </v-btn>
    <v-row v-if="ueInfo && ueInfo.length == 0" class="mt-4 ml-3">
      <b>
        UE Sessions are not able to be generated please check your pcap file
      </b>
    </v-row>
    <v-row class="mt-3">
      <v-col v-for="(ue, i) in ueInfo" :key="i" cols="6" md="3">
        <v-card color="primary" class="mx-auto">
          <v-card-item>
            <div>
              <div class="text-h6 mb-1">{{ ue.ue_ip_addr_ipv4 }}</div>
              <v-divider></v-divider>
              <div class="text-overline white--text mb-1">
                <div class="ml-2" v-for="(value, key) in ue" :key="key">
                  {{ key }}: {{ value }}
                </div>
              </div>
            </div>
          </v-card-item>
        </v-card>
      </v-col>
    </v-row>
    <div class="mt-3" v-if="ipProtocolItems.length > 0">
      <v-btn @click="getAssessments"> Set Roles in IPs </v-btn>
      <Assessments :results="roles" />
    </div>
  </v-container>
</template>

<script>
import Assessments from "../components/Assessments.vue";
export default {
  computed: {
    ipProtocolItems() {
      if (!this.analysis?.ip_protocols) return [];
      return Object.entries(this.analysis.ip_protocols).map(
        ([ip, protocols]) => ({
          ip,
          protocols,
        })
      );
    },
  },
  data() {
    return {
      file: null,
      analysis: null,
      graphData: null,
      ipProtocolHeaders: [
        { text: "IP Address", value: "ip" },
        { text: "Protocols Sent", value: "protocols" },
      ],
      ueInfo: null,
      loading: false,
      showUEButon: false,
      expanded: [],
      roles: null,
    };
  },
  methods: {
    handleFile(file) {
      this.file = file;
    },

    async sendFile() {
      this.loading = true;
      if (!this.file) return;

      try {
        const formData = new FormData();
        formData.append("file", this.file);

        const response = await fetch("http://127.0.0.1:5000/analyze", {
          method: "POST",
          body: formData,
        });

        const data = await response.json();

        if (!response.ok) {
          alert("Error: " + (data.error || "Unknown error"));
          return;
        }

        this.analysis = data.analysis;
      } catch (err) {
        alert("Upload failed: " + err.message);
      }
      this.loading = false;
      this.showUEButon = true;
    },

    async downloadConversations() {
      try {
        const response = await fetch(
          "http://127.0.0.1:5000/conversations.json"
        );
        if (!response.ok) {
          throw new Error("Failed to fetch conversation graph");
        }

        const data = await response.json();
        this.graphData = data;
      } catch (err) {
        alert("Error fetching graph data: " + err.message);
      }
    },

    async getUeInfo() {
      try {
        const response = await fetch("http://127.0.0.1:5000/ue_sessions");
        if (!response.ok) {
          throw new Error("Failed to fetch UE Sessions");
        }

        const data = await response.json();
        this.ueInfo = data;
      } catch (err) {
        alert("Error fetching UE data: " + err.message);
      }
    },
    async getAssessments() {
      try {
        const response = await fetch("http://127.0.0.1:5000/role_assessment");
        if (!response.ok) {
          throw new Error("Failed to fetch role assessments");
        }

        const data = await response.json();
        this.roles = data;
      } catch (err) {
        alert("Error fetching roles data: " + err.message);
      }
    },
  },
};
</script>
