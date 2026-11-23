/**
 * Unit tests for components/WarningsAlert.vue, which shows the backend's
 * "warnings" list (parts of an analysis that failed while the rest succeeded).
 */

import { shallowMount } from '@vue/test-utils'
import WarningsAlert from '~/components/WarningsAlert.vue'

// Render v-alert as a plain element so its slot content is visible.
const stubs = { 'v-alert': { template: '<div class="v-alert-stub"><slot /></div>' } }

function mountAlert(propsData) {
  return shallowMount(WarningsAlert, { propsData, stubs })
}

describe('WarningsAlert', () => {
  test('renders nothing without warnings', () => {
    expect(mountAlert({ warnings: [] }).find('.v-alert-stub').exists()).toBe(false)
    expect(mountAlert({}).find('.v-alert-stub').exists()).toBe(false)
  })

  test('lists every warning', () => {
    const warnings = [
      'UE identity extraction failed; no UE sessions were stored.',
      'Privacy record extraction failed; privacy records are empty.',
    ]
    const items = mountAlert({ warnings }).findAll('li')
    expect(items).toHaveLength(2)
    expect(items.at(0).text()).toBe(warnings[0])
    expect(items.at(1).text()).toBe(warnings[1])
  })

  test('shows the default title, or a custom one', () => {
    expect(mountAlert({ warnings: ['x'] }).text()).toContain('may be incomplete')
    expect(mountAlert({ warnings: ['x'], title: 'Heads up' }).text()).toContain('Heads up')
  })
})
