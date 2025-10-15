<template>
  <footer class="footer">
    <v-container>
      <v-row>
        <!-- Column 1 -->
        <v-col cols="12" sm="4" class="text-center">
          <h4>Site</h4>
          <router-link to="/">Home</router-link><br />
          <router-link to="/about">About</router-link><br />
          <router-link to="/contact">Contact</router-link>
        </v-col>

        <!-- Column 2 -->
        <v-col cols="12" sm="4" class="text-center">
          <h4>Resources</h4>
          <router-link to="/blog">Blog</router-link><br />
          <router-link to="/faq">FAQ</router-link><br />
          <router-link to="/support">Support</router-link>
        </v-col>

        <!-- Column 3 -->
        <v-col cols="12" sm="4" class="text-center">
          <h4>Legal</h4>
          <router-link to="/terms">Terms</router-link><br />
          <router-link to="/privacy">Privacy</router-link><br />
          <router-link to="/cookies">Cookies</router-link>
        </v-col>
      </v-row>

      <!-- Logos Row -->
      <v-row class="justify-center my-4">
        <v-img
          src="/6g_logo.png"
          alt="Logo 1"
          contain
          max-width="60"
          class="mx-4"
        />
        <v-img
          src="/6gsns.png"
          alt="Logo 2"
          contain
          max-width="100"
          class="mx-4"
        />
        <v-img
          src="/co_funded.png"
          alt="Logo 3"
          contain
          max-width="150"
          class="mx-4"
        />
        <v-img
          src="/UTH_logo.png"
          alt="Logo 3"
          contain
          max-width="100"
          class="mx-4"
        />
      </v-row>

      <!-- Bottom Text -->
      <v-row justify="center" class="text-center">
        <v-col cols="12">
          <p><b>2025 &copy; UTH – XTRUST-6G</b></p>
        </v-col>
      </v-row>
    </v-container>
  </footer>
</template>

<style scoped>
.footer {
  background-color: #f5f5f5;
  color: #333;
  padding: 2em 1em;
}

a {
  color: inherit;
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}
</style>
