<template>
  <v-app>
    <AppHeader />
    <v-main>
      <v-container style="max-width: 100% !important; padding: 0% !important">
        <Nuxt />
      </v-container>
    </v-main>
    <AppFooter />
  </v-app>
</template>

<script>
import AppFooter from "../components/AppFooter.vue";
import AppHeader from "../components/AppHeader.vue";

export default {
  components: {
    AppHeader,
    AppFooter,
  },
  name: "DefaultLayout",
  data() {
    return {
      title: "Network Analyzer",
    };
  },
};
</script>
