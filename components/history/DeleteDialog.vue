<template>
  <v-dialog :value="value" max-width="420" persistent @input="$emit('input', $event)">
    <v-card class="rounded-xl pa-2" style="border: 1px solid var(--border)">
      <v-card-title class="text-h6">
        <v-icon color="error" class="mr-2">mdi-alert-circle-outline</v-icon>
        Confirm Delete
      </v-card-title>
      <v-card-text>
        This will permanently delete
        <strong>{{ name }}</strong>
        and its file on disk. This cannot be undone.
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn text @click="$emit('input', false)">Cancel</v-btn>
        <v-btn color="error" :loading="loading" @click="$emit('confirm')">Delete</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script>
export default {
  name: "DeleteDialog",
  props: {
    value: { type: Boolean, default: false },
    name: { type: String, default: "" },
    loading: { type: Boolean, default: false },
  },
};
</script>
