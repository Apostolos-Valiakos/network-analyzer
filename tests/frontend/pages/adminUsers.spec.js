/**
 * pages/admin/users.vue: a failed user list load is shown as an error, not as
 * an empty "No users found" table.
 */

import { shallowMount } from '@vue/test-utils'
import UsersPage from '~/pages/admin/users.vue'

const VUETIFY = 'v-alert v-avatar v-btn v-card v-card-actions v-card-text v-card-title v-chip v-col v-container v-data-table v-dialog v-icon v-row v-spacer v-switch v-text-field'.split(' ')

function mountPage(json) {
  return shallowMount(UsersPage, {
    stubs: VUETIFY,
    mocks: {
      $api: { json },
      $store: { state: { auth: { token: null } } },
    },
  })
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0))

describe('admin users list', () => {
  test('a failed load shows the error message', async () => {
    const wrapper = mountPage(jest.fn().mockRejectedValue(new Error('Server error (500)')))
    await flush()

    expect(wrapper.vm.users).toEqual([])
    expect(wrapper.vm.loadError).toBe('Server error (500)')
    expect(wrapper.text()).toContain('Server error (500)')
  })

  test('a successful reload clears an earlier error', async () => {
    const json = jest
      .fn()
      .mockRejectedValueOnce(new Error('Server error (500)'))
      .mockResolvedValue([{ id: 1, username: 'admin', is_admin: true }])
    const wrapper = mountPage(json)
    await flush()

    await wrapper.vm.fetchUsers()

    expect(wrapper.vm.loadError).toBeNull()
    expect(wrapper.vm.users).toHaveLength(1)
  })
})
