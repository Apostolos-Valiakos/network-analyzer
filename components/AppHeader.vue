<template>
  <div>
    <!-- Mobile drawer -->
    <v-navigation-drawer
      v-model="drawer"
      app
      temporary
      color="#0f172a"
      dark
      width="260"
    >
      <div class="pa-4 d-flex align-center">
        <v-img
          src="/6g_logo.png"
          alt="Logo"
          contain
          max-width="32"
          class="mr-2"
        />
        <span class="text-subtitle-1 font-weight-bold white--text"
          >Privacy Enhanced Network Profiler</span
        >
      </div>
      <v-divider style="border-color: rgba(255, 255, 255, 0.1)" />

      <v-list nav dense class="mt-2">
        <v-list-item
          v-for="item in visibleNavItems"
          :key="item.href || item.to"
          v-bind="item.href
            ? { href: item.href, target: '_blank', rel: 'noopener noreferrer' }
            : { to: item.to, exact: true }"
          active-class="drawer-active"
          class="mb-1 rounded-lg"
        >
          <v-list-item-icon>
            <v-icon
              small
              :color="!item.href && isActive(item.to) ? '#38bdf8' : 'rgba(255,255,255,0.6)'"
            >
              {{ item.icon }}
            </v-icon>
          </v-list-item-icon>
          <v-list-item-content>
            <v-list-item-title
              :class="
                !item.href && isActive(item.to)
                  ? 'white--text font-weight-bold'
                  : 'grey--text text--lighten-1'
              "
              style="font-size: 0.875rem"
            >
              {{ item.label }}
            </v-list-item-title>
          </v-list-item-content>
        </v-list-item>
      </v-list>

      <template v-slot:append>
        <v-divider style="border-color: rgba(255, 255, 255, 0.1)" />
        <div class="pa-4 d-flex align-center justify-space-between">
          <div class="d-flex align-center">
            <v-icon small color="rgba(255,255,255,0.5)" class="mr-2"
              >mdi-account-circle</v-icon
            >
            <span class="text-caption grey--text text--lighten-1">{{
              username
            }}</span>
            <v-chip v-if="isAdmin" x-small color="amber darken-2" class="ml-2"
              >admin</v-chip
            >
          </div>
          <div class="d-flex align-center">
            <v-btn icon x-small @click="toggleTheme" class="mr-1">
              <v-icon small color="rgba(255,255,255,0.5)">{{
                isDark ? "mdi-weather-sunny" : "mdi-weather-night"
              }}</v-icon>
            </v-btn>
            <v-btn icon x-small @click="logout">
              <v-icon small color="rgba(255,255,255,0.5)">mdi-logout</v-icon>
            </v-btn>
          </div>
        </div>
      </template>
    </v-navigation-drawer>

    <!-- Main app bar -->
    <v-app-bar
      app
      dark
      elevation="0"
      height="60"
      style="
        background: #0f172a;
        border-bottom: 1px solid rgba(255, 255, 255, 0.07);
      "
    >
      <!-- Mobile hamburger -->
      <v-btn icon dark class="d-flex d-md-none mr-1" @click="drawer = !drawer">
        <v-icon>mdi-menu</v-icon>
      </v-btn>

      <!-- Logo -->
      <router-link to="/" class="d-flex align-center text-decoration-none mr-4">
        <v-img
          src="/6g_logo.png"
          alt="Logo"
          contain
          max-width="32"
          class="mr-2"
        />
        <span
          class="text-subtitle-2 font-weight-bold white--text d-none d-sm-inline"
        >
          Privacy Enhanced Network Profiler
        </span>
      </router-link>

      <!-- Desktop nav -->
      <div class="d-none d-md-flex align-center" style="gap: 2px">
        <template v-for="item in visibleNavItems">
          <!-- Section divider before "Info" group -->
          <v-divider
            v-if="item.dividerBefore"
            :key="'div-' + (item.to || item.label)"
            vertical
            style="
              border-color: rgba(255, 255, 255, 0.12);
              height: 24px;
              align-self: center;
              margin: 0 6px;
            "
          />

          <v-btn
            :key="item.href || item.to"
            text
            dark
            v-bind="item.href
              ? { href: item.href, target: '_blank', rel: 'noopener noreferrer' }
              : { to: item.to, exact: true }"
            small
            class="nav-btn"
            :class="{ 'nav-btn--active': !item.href && isActive(item.to) }"
          >
            <v-icon left x-small>{{ item.icon }}</v-icon>
            {{ item.label }}
          </v-btn>
        </template>
      </div>

      <v-spacer />

      <!-- User section -->
      <div class="d-flex align-center" style="gap: 8px">
        <div class="d-none d-sm-flex align-center">
          <v-icon small color="rgba(255,255,255,0.45)" class="mr-1"
            >mdi-account-circle-outline</v-icon
          >
          <span
            class="text-caption font-weight-medium"
            style="color: rgba(255, 255, 255, 0.7)"
          >
            {{ username }}
          </span>
          <v-chip
            v-if="isAdmin"
            x-small
            color="amber darken-1"
            class="ml-2"
            style="font-weight: 700; letter-spacing: 0.4px"
          >
            ADMIN
          </v-chip>
        </div>

        <!-- Theme toggle -->
        <v-btn
          icon
          small
          dark
          @click="toggleTheme"
          :title="isDark ? 'Switch to light mode' : 'Switch to dark mode'"
          style="margin-right: 4px"
        >
          <v-icon small>{{
            isDark ? "mdi-weather-sunny" : "mdi-weather-night"
          }}</v-icon>
        </v-btn>

        <v-btn
          small
          outlined
          dark
          @click="logout"
          style="
            border-color: rgba(255, 255, 255, 0.2);
            font-size: 0.75rem;
            letter-spacing: 0.3px;
          "
        >
          <v-icon left x-small>mdi-logout</v-icon>
          Logout
        </v-btn>
      </div>
    </v-app-bar>
  </div>
</template>

<script>
export default {
  data() {
    return {
      drawer: false,
      navItems: [
        { to: "/", icon: "mdi-home-outline", label: "Home", exact: true },
        { to: "/analyze", icon: "mdi-file-upload-outline", label: "Analyze" },
        { to: "/history", icon: "mdi-history", label: "History" },
        { to: "/realTime", icon: "mdi-access-point", label: "Real Time" },
        {
          to: "/continuous_monitoring",
          icon: "mdi-monitor-dashboard",
          label: "Monitoring",
        },
        {
          to: "/about",
          icon: "mdi-information-outline",
          label: "About",
          dividerBefore: true,
        },
        { to: "/contact", icon: "mdi-email-outline", label: "Contact" },
        {
          href: `${process.env.VUE_APP_API_BASE_URL || 'http://127.0.0.1:5555'}/apidocs`,
          icon: "mdi-book-open-variant",
          label: "API Docs",
        },
        {
          to: "/admin/users",
          icon: "mdi-shield-account-outline",
          label: "Users",
          adminOnly: true,
          dividerBefore: true,
        },
      ],
    };
  },

  mounted() {
    const saved = localStorage.getItem("theme");
    if (saved !== null) {
      this.$vuetify.theme.dark = saved === "dark";
    }
  },

  computed: {
    username() {
      return this.$store.state.auth.username;
    },
    isAdmin() {
      return this.$store.state.auth.isAdmin;
    },
    visibleNavItems() {
      return this.navItems.filter((item) => !item.adminOnly || this.isAdmin);
    },
    isDark() {
      return this.$vuetify.theme.dark;
    },
  },

  methods: {
    isActive(path) {
      if (path === "/") return this.$route.path === "/";
      return this.$route.path.startsWith(path);
    },
    toggleTheme() {
      this.$vuetify.theme.dark = !this.$vuetify.theme.dark;
      localStorage.setItem(
        "theme",
        this.$vuetify.theme.dark ? "dark" : "light"
      );
    },
    logout() {
      this.$store.commit("auth/CLEAR");
      localStorage.removeItem("auth_token");
      localStorage.removeItem("auth_is_admin");
      localStorage.removeItem("auth_username");
      this.$router.push("/login");
    },
  },
};
</script>

<style scoped>
.nav-btn {
  text-transform: none;
  letter-spacing: 0.3px;
  font-weight: 500;
  font-size: 0.8125rem;
  color: rgba(255, 255, 255, 0.6) !important;
  border-radius: 6px;
  transition: color 0.15s, background 0.15s;
}

.nav-btn:hover {
  color: rgba(255, 255, 255, 0.95) !important;
  background: rgba(255, 255, 255, 0.07) !important;
}

.nav-btn--active {
  color: #38bdf8 !important;
  background: rgba(56, 189, 248, 0.1) !important;
}

.nav-btn--active .v-icon {
  color: #38bdf8 !important;
}

/* Drawer active state */
.drawer-active {
  background: rgba(56, 189, 248, 0.12) !important;
}
</style>
