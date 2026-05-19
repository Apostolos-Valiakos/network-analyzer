<template>
  <v-container class="fill-height" fluid>
    <v-row align="center" justify="center" class="fill-height">
      <v-col cols="12" sm="8" md="5" lg="4">
        <v-card class="login-card rounded-xl">
          <v-card-title class="pa-6 pb-2">
            <v-row align="center" no-gutters>
              <v-col>
                <div class="d-flex align-center mb-1">
                  <v-icon color="primary" class="mr-2"
                    >mdi-shield-lock-outline</v-icon
                  >
                  <div class="text-h5 font-weight-bold">
                    Privacy Enhanced Network Profiler
                  </div>
                </div>
                <div class="text-subtitle-2 mt-1 text-dim">
                  Sign in to your account
                </div>
              </v-col>
            </v-row>
          </v-card-title>

          <v-card-text class="pa-6 pt-4">
            <v-alert v-if="error" type="error" dense class="mb-4" border="left">
              {{ error }}
            </v-alert>

            <v-text-field
              v-model="username"
              label="Username"
              prepend-icon="mdi-account"
              outlined
              dense
              :disabled="loading"
              @keyup.enter="login"
            />

            <v-text-field
              v-model="password"
              label="Password"
              prepend-icon="mdi-lock"
              :type="showPassword ? 'text' : 'password'"
              :append-icon="showPassword ? 'mdi-eye' : 'mdi-eye-off'"
              outlined
              dense
              :disabled="loading"
              @click:append="showPassword = !showPassword"
              @keyup.enter="login"
            />
          </v-card-text>

          <v-card-actions class="pa-6 pt-0">
            <v-btn
              color="primary"
              block
              large
              :loading="loading"
              :disabled="!username || !password"
              @click="login"
            >
              Sign In
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
export default {
  layout: "empty",

  data() {
    return {
      username: "",
      password: "",
      showPassword: false,
      loading: false,
      error: null,
      apiBaseUrl: process.env.VUE_APP_API_BASE_URL || "http://127.0.0.1:5555",
    };
  },

  methods: {
    async login() {
      if (!this.username || !this.password) return;
      this.loading = true;
      this.error = null;
      try {
        const res = await fetch(`${this.apiBaseUrl}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: this.username,
            password: this.password,
          }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Login failed");

        localStorage.setItem("auth_token", data.access_token);
        localStorage.setItem("auth_is_admin", data.is_admin ? "true" : "false");
        localStorage.setItem("auth_username", this.username);

        this.$store.commit("auth/SET", {
          token: data.access_token,
          isAdmin: data.is_admin,
          username: this.username,
        });

        this.$router.push("/");
      } catch (err) {
        this.error = err.message;
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>

<style scoped>
.fill-height {
  min-height: 100vh;
  background: var(--app-bg);
}
.login-card {
  background-color: var(--surface) !important;
  border: 1px solid var(--border) !important;
}
</style>
