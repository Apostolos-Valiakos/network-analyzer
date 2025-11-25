<template>
  <div>
    <v-card class="pa-6 mb-8 rounded-xl connection-card">
      <h3 class="text-h6 font-weight-bold mb-4 text-primary">
        <v-icon color="primary" class="mr-2">mdi-file-export</v-icon>
        Export & Final Results
      </h3>

      <p class="text-subtitle-1 mb-4">
        You can export the final <b>Roles</b> data or re-download the
        <b>.pcap</b> file.
      </p>

      <v-divider class="my-4"></v-divider>

      <v-select
        class="futuristic-input mb-6"
        :items="['json', 'csv']"
        label="Select Export File Type"
        v-model="localFileType"
      ></v-select>

      <div class="d-flex flex-wrap ga-4">
        <v-btn color="green" class="white--text control-btn" @click="saveRoles">
          <v-icon start>mdi-content-save</v-icon>
          Download Roles ({{ localFileType.toUpperCase() }})
        </v-btn>

        <v-btn
          color="blue"
          class="white--text control-btn"
          @click="downloadPcap"
        >
          <v-icon start>mdi-download</v-icon>
          Download PCAP File
        </v-btn>
      </div>

      <v-divider class="my-6"></v-divider>

      <div class="text-center pa-4">
        <v-icon size="48" color="primary">mdi-check-decagram</v-icon>
        <p class="text-subtitle-1 text-medium-emphasis mt-2">
          All analysis completed successfully.
        </p>
      </div>
    </v-card>

    <div class="d-flex ga-4 mt-4">
      <v-btn color="secondary" @click="$emit('prev')" class="mx-2 control-btn">
        <v-icon start>mdi-arrow-left</v-icon> Previous
      </v-btn>
      <v-btn color="primary" @click="$emit('restart')" class="mx-2 control-btn">
        <v-icon start>mdi-restart</v-icon> Start Over
      </v-btn>
    </div>
  </div>
</template>

<script>
export default {
  props: {
    filename: String,
    fileType: String,
  },

  emits: ["prev", "restart", "download-pcap", "save-roles"],

  data() {
    return { localFileType: this.fileType };
  },

  watch: {
    fileType(v) {
      this.localFileType = v;
    },
  },

  methods: {
    downloadPcap() {
      this.$emit("download-pcap");
    },
    saveRoles() {
      this.$emit("save-roles", this.localFileType);
    },
  },

  created() {
    this.$watch("localFileType", (v) => this.$emit("update:fileType", v));
  },
};
</script>
