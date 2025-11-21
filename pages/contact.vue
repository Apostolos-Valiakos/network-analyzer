<template>
  <v-container class="futuristic-light-container">
    <v-row>
      <v-col cols="12" md="8">
        <v-card class="data-card pa-6">
          <h2 class="text-h5 mb-4 font-weight-bold">Contact Us</h2>
          <v-form ref="form" v-model="valid" lazy-validation>
            <div class="realtime-view mb-6">
              <v-icon :color="formStatusColor" large class="mb-2">{{
                formStatusIcon
              }}</v-icon>
              <p class="font-weight-medium" :class="`text--${formStatusColor}`">
                Status: {{ formStatusText }}
              </p>
            </div>

            <v-text-field
              v-model="name"
              :rules="nameRules"
              label="Designated Sender Name"
              required
              outlined
              dense
              class="mb-3"
            ></v-text-field>

            <v-text-field
              v-model="email"
              :rules="emailRules"
              label="Recipient Address (Email)"
              required
              outlined
              dense
              class="mb-3"
            ></v-text-field>

            <v-textarea
              v-model="message"
              :rules="messageRules"
              label="Transmission Payload (Message)"
              required
              outlined
              dense
              rows="4"
              class="mb-4"
            ></v-textarea>

            <div class="controls-section">
              <v-btn
                :disabled="!valid || loading"
                color="primary"
                class="control-btn"
                @click="submitForm"
                :loading="loading"
              >
                <v-icon left>mdi-send</v-icon>
                Transmit Data
              </v-btn>

              <v-btn
                color="secondary"
                class="control-btn"
                @click="resetForm"
                outlined
              >
                <v-icon left>mdi-eraser</v-icon>
                Clear Fields
              </v-btn>
            </div>
          </v-form>
        </v-card>
      </v-col>

      <v-col cols="12" md="4">
        <v-card class="data-card pa-5">
          <h3 class="text-subtitle-1 font-weight-bold mb-3">
            Direct Access Points
          </h3>
          <div class="packet-list">
            <div class="packet-item">
              <v-icon small color="blue-grey darken-1" class="mr-2">
                mdi-email-outline
              </v-icon>
              <span class="font-mono text-body-2">avaliakos@uth.gr</span>
            </div>
            <div class="packet-item">
              <v-icon small color="blue-grey darken-1" class="mr-2">
                mdi-phone-outline
              </v-icon>
              <span class="font-mono text-body-2">+1 (555) 123-4567</span>
            </div>
            <div class="packet-item">
              <v-icon small color="blue-grey darken-1" class="mr-2"
                >mdi-map-marker-outline</v-icon
              >
              <span class="font-mono text-body-2"> Gaiopolis, Larisa </span>
            </div>
          </div>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
export default {
  name: "ContactInterface",
  data: () => ({
    valid: true,
    loading: false,
    formSubmitted: false,
    name: "",
    email: "",
    message: "",
    nameRules: [
      (v) => !!v || "Name is required for identification.",
      (v) => (v && v.length <= 50) || "Name must be less than 50 characters.",
    ],
    emailRules: [
      (v) => !!v || "E-mail is required for reply transmission.",
      (v) => /.+@.+\..+/.test(v) || "E-mail must be valid syntax.",
    ],
    messageRules: [(v) => !!v || "Transmission payload cannot be empty."],
  }),
  computed: {
    formStatusColor() {
      if (this.loading) return "warning";
      if (this.formSubmitted) return "success";
      if (this.name || this.email || this.message) return "primary";
      return "secondary";
    },
    formStatusIcon() {
      if (this.loading) return "mdi-clock-time-three-outline";
      if (this.formSubmitted) return "mdi-check-circle";
      if (this.name || this.email || this.message)
        return "mdi-pencil-box-multiple";
      return "mdi-form-select";
    },
    formStatusText() {
      if (this.loading) return "Processing... Hold for System Confirmation.";
      if (this.formSubmitted)
        return "Transmission Confirmed. Awaiting Response.";
      if (this.name || this.email || this.message)
        return "Data Entry In Progress.";
      return "Awaiting User Input.";
    },
  },
  methods: {
    async submitForm() {
      if (this.$refs.form.validate()) {
        this.loading = true;

        await new Promise((resolve) => setTimeout(resolve, 2000));

        this.loading = false;
        this.formSubmitted = true;
        console.log("Data Transmitted:", {
          name: this.name,
          email: this.email,
          message: this.message,
        });

        // Optionally clear form after submission
        this.resetForm();
      }
    },
    resetForm() {
      this.$refs.form.reset();
      this.formSubmitted = false;
    },
  },
};
</script>

<style scoped>
/* NOTE: The provided styles are inserted here.
 * For production, consider moving them to a global stylesheet or SCSS module
 * to avoid duplication if used across multiple components.
 */
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
  display: flex;
  align-items: center;
}
.packet-item:last-child {
  border-bottom: none;
}
.font-mono {
  font-family: monospace;
}

/* NEW: Style for gap in interface controls */
.gap-3 {
  gap: 12px;
}
</style>
