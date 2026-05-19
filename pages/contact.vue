<template>
  <v-container class="page-container">
    <div class="d-flex align-center mb-6">
      <v-icon size="32" color="primary" class="mr-3">mdi-email-outline</v-icon>
      <div>
        <h1 class="text-h5 font-weight-bold mb-0">Contact Us</h1>
        <p class="text-caption mb-0 text-dim">Get in touch with the team</p>
      </div>
    </div>
    <v-row>
      <v-col cols="12" md="8">
        <v-card class="themed-card pa-6">
          <v-form ref="form" v-model="valid" lazy-validation>
            <div class="themed-highlight mb-6">
              <v-icon :color="formStatusColor" large class="mb-2">{{
                formStatusIcon
              }}</v-icon>
              <p class="font-weight-medium" :class="`${formStatusColor}--text`">
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
        <v-card class="themed-accent-card pa-5">
          <h3 class="text-subtitle-1 font-weight-bold mb-4 primary--text">
            <v-icon color="primary" small class="mr-1">mdi-access-point</v-icon>
            Direct Access Points
          </h3>
          <div class="contact-list">
            <div class="contact-item">
              <v-icon small color="primary" class="mr-2">mdi-email-outline</v-icon>
              <span class="font-mono text-body-2">avaliakos@uth.gr</span>
            </div>
            <div class="contact-item">
              <v-icon small color="primary" class="mr-2">mdi-phone-outline</v-icon>
              <span class="font-mono text-body-2">+1 (555) 123-4567</span>
            </div>
            <div class="contact-item">
              <v-icon small color="primary" class="mr-2">mdi-map-marker-outline</v-icon>
              <span class="font-mono text-body-2">Gaiopolis, Larisa</span>
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

.themed-highlight {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 16px;
  border: 1px dashed var(--highlight-border);
  border-radius: 16px;
  background: var(--highlight-bg);
}

.contact-list {
  border-radius: 12px;
  padding: 4px 0;
}

.contact-item {
  display: flex;
  align-items: center;
  padding: 10px 0;
  border-bottom: 1px solid var(--packet-item-border);
}

.contact-item:last-child {
  border-bottom: none;
}

.font-mono {
  font-family: monospace;
  color: var(--text-secondary);
}
</style>
