<template>
  <v-app-bar app color="primary" dark>
    <!-- Logo on the left -->
    <v-app-bar-nav-icon>
      <v-img src="/6g_logo.png" alt="Logo" contain max-width="40"></v-img>
    </v-app-bar-nav-icon>

    <!-- Title or left space -->
    <v-toolbar-title class="ml-2">Network Analyzer</v-toolbar-title>

    <v-spacer></v-spacer>

    <!-- Navigation links -->
    <router-link to="/analyze" class="text-none">
      <v-btn text>Analyze Network</v-btn>
    </router-link>

    <router-link to="/about" class="text-none">
      <v-btn text>About</v-btn>
    </router-link>
    <router-link to="/contact" class="text-none">
      <v-btn text>Contact</v-btn>
    </router-link>
  </v-app-bar>
</template>

<script>
export default {
  data() {
    return {};
  },
};
</script>

<style scoped></style>
