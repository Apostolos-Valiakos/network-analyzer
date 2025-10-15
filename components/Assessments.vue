<template>
  <v-container fluid>
    <v-data-table
      v-if="results && results.length > 0"
      :headers="headers"
      :items="results"
      item-key="ip"
      show-expand
      :expanded.sync="expanded"
      dense
      disable-pagination
      hide-default-footer
      class="elevation-1"
    >
      <!-- Roles column as chips -->
      <template #item.roles="{ item }">
        <v-chip
          v-for="(role, index) in item.roles"
          :key="index"
          class="me-2 mb-1"
          color="primary"
          variant="tonal"
          small
        >
          {{ role }}
        </v-chip>
      </template>

      <!-- Expanded content -->
      <template #expanded-item="{ item }">
        <td :colspan="headers.length" class="pa-4">
          <div>
            <strong>All Roles:</strong>
            <div class="my-2">
              <v-chip
                v-for="(role, index) in item.roles"
                :key="'expanded-' + index"
                class="me-2 mb-2"
                color="secondary"
                variant="tonal"
                small
              >
                {{ role }}
              </v-chip>
            </div>
            <strong>Reasoning:</strong>
            <v-alert type="info" variant="tonal" class="mt-2" dense>
              {{ item.reasoning }}
            </v-alert>
          </div>
        </td>
      </template>
    </v-data-table>
  </v-container>
</template>

<script>
export default {
  name: "Assessments",
  props: {
    results: {
      type: Array,
      required: true,
      default: () => [],
    },
  },
  data() {
    return {
      expanded: [],
      headers: [
        { text: "IP Address", value: "ip" },
        { text: "Roles", value: "roles" },
      ],
    };
  },
};
</script>

<style scoped>
.v-data-table {
  font-size: 0.9rem;
}
</style>
