/** Tests for components/history/HistoryTable.vue and ResultDialog.vue. */
import { shallowMount } from '@vue/test-utils'
import HistoryTable from '~/components/history/HistoryTable.vue'
import ResultDialog from '~/components/history/ResultDialog.vue'

describe('HistoryTable', () => {
  function mountTable(props) {
    return shallowMount(HistoryTable, {
      propsData: { headers: [], items: [], ...props },
    })
  }

  test('offers the requested actions in order', () => {
    const wrapper = mountTable({ actions: ['view', 'download', 'delete'] })
    expect(wrapper.vm.shownActions.map((a) => [a.key, a.label])).toEqual([
      ['view', 'View Results'],
      ['download', 'Download PCAP'],
      ['delete', 'Delete'],
    ])
    expect(wrapper.vm.shownActions[2].color).toBe('error')
  })

  test('disables view without a result and re-cluster without a pcap', () => {
    const wrapper = mountTable({ actions: ['view', 'recluster', 'download'] })
    const [view, recluster, download] = wrapper.vm.shownActions
    expect(view.disabled({ has_result: false })).toBe(true)
    expect(view.disabled({ has_result: true })).toBe(false)
    expect(recluster.disabled({ pcap_id: null })).toBe(true)
    expect(recluster.disabled({ pcap_id: 'abc' })).toBe(false)
    expect(download.disabled({})).toBe(false)
  })
})

describe('ResultDialog', () => {
  function mountDialog(data) {
    return shallowMount(ResultDialog, {
      propsData: { value: true, type: 'pcap', data, loading: false },
      stubs: { 'v-dialog': { template: '<div><slot /></div>' } },
    })
  }

  test('passes stored warnings to the warnings alert', () => {
    const wrapper = mountDialog({ total_packets: 3, roles: {}, warnings: ['partial roles'] })
    expect(wrapper.findComponent({ name: 'WarningsAlert' }).props('warnings')).toEqual([
      'partial roles',
    ])
  })

  test('passes an empty list when the result has no warnings', () => {
    const wrapper = mountDialog({ total_packets: 3, roles: {} })
    expect(wrapper.findComponent({ name: 'WarningsAlert' }).props('warnings')).toEqual([])
  })
})
