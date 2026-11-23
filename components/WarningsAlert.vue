<template>
  <v-alert
    v-if="warnings && warnings.length"
    type="warning"
    outlined
    dense
    dismissible
    class="mb-4 warnings-alert"
  >
    <div class="font-weight-medium">{{ title }}</div>
    <ul class="mt-1 mb-0">
      <li v-for="(w, i) in warnings" :key="i">{{ w }}</li>
    </ul>
  </v-alert>
</template>

<script>
// Shows the "warnings" list the backend adds when part of an analysis failed
// while the rest succeeded (e.g. UE extraction or saving a result).
export default {
  name: "WarningsAlert",
  props: {
    warnings: { type: Array, default: () => [] },
    title: {
      type: String,
      default: "Completed with problems. The results below may be incomplete:",
    },
  },
};
</script>
