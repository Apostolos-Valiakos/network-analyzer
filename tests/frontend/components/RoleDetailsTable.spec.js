/**
 * Unit tests for components/RoleDetailsTable.vue: per-IP roles with the
 * Kubernetes pod and hint (k8s field of the role results).
 */

import { shallowMount } from '@vue/test-utils'
import RoleDetailsTable from '~/components/RoleDetailsTable.vue'

const DETAILS = {
  '10.244.0.31': {
    role: 'AMF', confidence: 0.99, reasoning: 'NGAP; pod agrees',
    k8s: { namespace: 'team-5g', pod: 'open5gs-amf-abc', hint_role: 'AMF' },
  },
  '10.244.0.40': {
    role: 'SMF', confidence: 0.95, reasoning: 'PFCP',
    k8s: { namespace: 'team-5g', pod: 'open5gs-upf-0', hint_role: 'UPF', k8s_mismatch: true },
  },
  '10.244.1.9': {
    role: 'Unidentified', confidence: 0, reasoning: 'none',
    k8s: { namespace: 'team-ric', pod: 'flexric-ric-0', hint_role: 'NEAR_RT_RIC', suggested_role: 'NEAR_RT_RIC' },
  },
  '10.96.0.10': {
    role: 'NRF', confidence: 0.93, reasoning: 'NFProfile',
    k8s: { namespace: 'team-5g', service: 'team-5g/open5gs-nrf' },
  },
  '10.16.0.5': { role: 'External/DN', confidence: 0.4, reasoning: 'plain' },
}

function mount(details = DETAILS) {
  return shallowMount(RoleDetailsTable, { propsData: { details } })
}

describe('RoleDetailsTable', () => {
  it('lists every IP with its role and pod', () => {
    const items = mount().vm.items
    expect(items.map((i) => i.ip)).toEqual(
      ['10.16.0.5', '10.244.0.31', '10.244.0.40', '10.244.1.9', '10.96.0.10'])
    const amf = items.find((i) => i.ip === '10.244.0.31')
    expect(amf.podLabel).toBe('team-5g/open5gs-amf-abc')
    expect(amf.hintRole).toBe('AMF')
    expect(amf.mismatch).toBe(false)
  })

  it('shows Service addresses and IPs without Kubernetes data', () => {
    const items = mount().vm.items
    expect(items.find((i) => i.ip === '10.96.0.10').podLabel).toBe('Service team-5g/open5gs-nrf')
    expect(items.find((i) => i.ip === '10.16.0.5').podLabel).toBe('')
  })

  it('marks mismatches and suggested roles', () => {
    const items = mount().vm.items
    expect(items.find((i) => i.ip === '10.244.0.40').mismatch).toBe(true)
    expect(items.find((i) => i.ip === '10.244.1.9').suggestedRole).toBe('NEAR_RT_RIC')
  })

  it('filters by namespace', async () => {
    const wrapper = mount()
    expect(wrapper.vm.namespaceItems).toEqual(['All namespaces', 'team-5g', 'team-ric'])
    await wrapper.setData({ namespace: 'team-ric' })
    expect(wrapper.vm.filteredItems.map((i) => i.ip)).toEqual(['10.244.1.9'])
    await wrapper.setData({ namespace: 'All namespaces' })
    expect(wrapper.vm.filteredItems).toHaveLength(5)
  })

  it('has pod columns and the filter only with Kubernetes data', () => {
    const withK8s = mount()
    expect(withK8s.vm.headers.map((h) => h.value)).toContain('pod')
    const without = mount({ '10.0.0.1': { role: 'AMF', confidence: 0.95, reasoning: 'x' } })
    expect(without.vm.hasK8s).toBe(false)
    expect(without.vm.headers.map((h) => h.value)).not.toContain('pod')
    expect(without.find('v-select-stub').exists()).toBe(false)
  })

  it('formats confidence', () => {
    const vm = mount().vm
    expect(vm.formatConfidence(0.9)).toBe('0.90')
    expect(vm.formatConfidence(undefined)).toBe('—')
  })
})
