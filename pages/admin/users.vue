<template>
  <v-container class="pa-6" max-width="900">
    <div class="d-flex align-center mb-6">
      <v-icon size="32" color="primary" class="mr-3">mdi-shield-account</v-icon>
      <div>
        <h1 class="text-h5 font-weight-bold mb-0">User Management</h1>
        <p class="text-caption grey--text mb-0">
          Create and manage user accounts
        </p>
      </div>
    </div>

    <!-- Create user card -->
    <v-card class="rounded-xl elevation-4 mb-8">
      <v-card-title class="pa-5 pb-3">
        <v-icon color="primary" class="mr-2">mdi-account-plus</v-icon>
        Create New User
      </v-card-title>

      <v-card-text class="pa-5 pt-2">
        <v-alert
          v-if="createError"
          type="error"
          dense
          border="left"
          class="mb-4"
        >
          {{ createError }}
        </v-alert>
        <v-alert
          v-if="createSuccess"
          type="success"
          dense
          border="left"
          class="mb-4"
        >
          {{ createSuccess }}
        </v-alert>

        <v-row>
          <v-col cols="12" md="5">
            <v-text-field
              v-model="form.username"
              label="Username"
              outlined
              dense
              prepend-inner-icon="mdi-account"
              :disabled="creating"
              hide-details="auto"
            />
          </v-col>
          <v-col cols="12" md="5">
            <v-text-field
              v-model="form.password"
              label="Password (min 8 characters)"
              outlined
              dense
              prepend-inner-icon="mdi-lock"
              :type="showPassword ? 'text' : 'password'"
              :append-icon="showPassword ? 'mdi-eye' : 'mdi-eye-off'"
              @click:append="showPassword = !showPassword"
              :disabled="creating"
              hide-details="auto"
            />
          </v-col>
          <v-col cols="12" md="2" class="d-flex align-center">
            <v-switch
              v-model="form.is_admin"
              label="Admin"
              color="warning"
              dense
              hide-details
              :disabled="creating"
            />
          </v-col>
        </v-row>
      </v-card-text>

      <v-card-actions class="pa-5 pt-0">
        <v-btn
          color="primary"
          :loading="creating"
          :disabled="!form.username || !form.password"
          @click="createUser"
        >
          <v-icon left>mdi-plus</v-icon>
          Create User
        </v-btn>
        <v-btn text :disabled="creating" @click="resetForm">Reset</v-btn>
      </v-card-actions>
    </v-card>

    <!-- Users table -->
    <v-card class="rounded-xl elevation-4">
      <v-card-title class="pa-5 pb-3 d-flex justify-space-between align-center">
        <div>
          <v-icon color="primary" class="mr-2">mdi-account-group</v-icon>
          Existing Users
        </div>
        <v-btn
          icon
          small
          :loading="loadingUsers"
          @click="fetchUsers"
          title="Refresh"
        >
          <v-icon>mdi-refresh</v-icon>
        </v-btn>
      </v-card-title>

      <v-card-text class="pa-0">
        <v-data-table
          :headers="headers"
          :items="users"
          :loading="loadingUsers"
          loading-text="Loading users..."
          no-data-text="No users found"
          hide-default-footer
          class="rounded-b-xl"
        >
          <template v-slot:item.username="{ item }">
            <div class="d-flex align-center">
              <v-avatar size="28" color="primary" class="mr-2">
                <span class="white--text text-caption font-weight-bold">
                  {{ item.username.charAt(0).toUpperCase() }}
                </span>
              </v-avatar>
              <span class="font-weight-medium">{{ item.username }}</span>
            </div>
          </template>

          <template v-slot:item.is_admin="{ item }">
            <v-chip
              x-small
              :color="item.is_admin ? 'amber darken-2' : 'grey lighten-1'"
              :dark="item.is_admin"
            >
              {{ item.is_admin ? "Admin" : "User" }}
            </v-chip>
          </template>

          <template v-slot:item.created_at="{ item }">
            <span class="text-caption grey--text">
              {{ formatDate(item.created_at) }}
            </span>
          </template>

          <template v-slot:item.actions="{ item }">
            <v-btn
              icon
              small
              color="error"
              :disabled="item.id === currentUserId || deletingId === item.id"
              :loading="deletingId === item.id"
              @click="confirmDelete(item)"
              title="Delete user"
            >
              <v-icon small>mdi-delete-outline</v-icon>
            </v-btn>
          </template>
        </v-data-table>
      </v-card-text>
    </v-card>

    <!-- Delete confirmation dialog -->
    <v-dialog v-model="deleteDialog" max-width="400">
      <v-card class="rounded-xl">
        <v-card-title class="text-h6">
          <v-icon color="error" class="mr-2">mdi-alert</v-icon>
          Delete User
        </v-card-title>
        <v-card-text>
          Are you sure you want to delete
          <strong>{{ deleteTarget && deleteTarget.username }}</strong
          >? This action cannot be undone.
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn text @click="deleteDialog = false">Cancel</v-btn>
          <v-btn color="error" @click="deleteUser">Delete</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-container>
</template>

<script>
export default {
  middleware: ["admin"],

  data() {
    return {
      apiBaseUrl: process.env.VUE_APP_API_BASE_URL || "http://127.0.0.1:5555",
      form: { username: "", password: "", is_admin: false },
      showPassword: false,
      creating: false,
      createError: null,
      createSuccess: null,

      users: [],
      loadingUsers: false,

      deletingId: null,
      deleteDialog: false,
      deleteTarget: null,

      headers: [
        { text: "Username", value: "username", sortable: true },
        { text: "Role", value: "is_admin", sortable: true },
        { text: "Created", value: "created_at", sortable: true },
        {
          text: "",
          value: "actions",
          sortable: false,
          align: "end",
          width: "60px",
        },
      ],
    };
  },

  computed: {
    currentUserId() {
      // Decode the user ID from the JWT stored in Vuex (set as string identity)
      const token = this.$store.state.auth.token;
      if (!token) return null;
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        return parseInt(payload.sub);
      } catch {
        return null;
      }
    },
  },

  mounted() {
    this.fetchUsers();
  },

  methods: {
    async fetchUsers() {
      this.loadingUsers = true;
      try {
        const res = await this.$apiFetch(`${this.apiBaseUrl}/auth/users`);
        if (!res.ok) throw new Error("Failed to load users");
        this.users = await res.json();
      } catch (err) {
        this.users = [];
      } finally {
        this.loadingUsers = false;
      }
    },

    async createUser() {
      this.creating = true;
      this.createError = null;
      this.createSuccess = null;
      try {
        const res = await this.$apiFetch(`${this.apiBaseUrl}/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(this.form),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to create user");
        this.createSuccess = `User "${data.username}" created successfully.`;
        this.resetForm();
        await this.fetchUsers();
      } catch (err) {
        this.createError = err.message;
      } finally {
        this.creating = false;
      }
    },

    resetForm() {
      this.form = { username: "", password: "", is_admin: false };
      this.createError = null;
      this.createSuccess = null;
    },

    confirmDelete(user) {
      this.deleteTarget = user;
      this.deleteDialog = true;
    },

    async deleteUser() {
      if (!this.deleteTarget) return;
      this.deleteDialog = false;
      this.deletingId = this.deleteTarget.id;
      try {
        const res = await this.$apiFetch(
          `${this.apiBaseUrl}/auth/users/${this.deleteTarget.id}`,
          { method: "DELETE" }
        );
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error || "Delete failed");
        }
        this.users = this.users.filter((u) => u.id !== this.deleteTarget.id);
      } catch (err) {
        this.createError = err.message;
      } finally {
        this.deletingId = null;
        this.deleteTarget = null;
      }
    },

    formatDate(iso) {
      if (!iso) return "—";
      return new Date(iso).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    },
  },
};
</script>
