/**
 * NetworkGraph, ModularityChart and PieChart: one ECharts instance per
 * component, one window resize listener, both released when the component is
 * destroyed. Before the fix NetworkGraph cleaned up in unmounted() (a Vue 3
 * hook Vue 2 never calls), and the other two added an anonymous listener on
 * every render and never disposed their chart.
 */

import { mount } from '@vue/test-utils'
import * as echarts from 'echarts'
import NetworkGraph from '~/components/NetworkGraph.vue'
import ModularityChart from '~/components/ModularityChart.vue'
import PieChart from '~/components/PieChart.vue'

jest.mock('echarts', () => ({ init: jest.fn() }))

let chart
let added
let removed

beforeEach(() => {
  chart = { setOption: jest.fn(), resize: jest.fn(), dispose: jest.fn() }
  echarts.init.mockReset().mockReturnValue(chart)
  added = jest.spyOn(window, 'addEventListener')
  removed = jest.spyOn(window, 'removeEventListener')
})

afterEach(() => {
  added.mockRestore()
  removed.mockRestore()
})

const resizeCalls = (spy) => spy.mock.calls.filter(([type]) => type === 'resize')

const graph = (n) => ({
  nodes: Array.from({ length: n }, (_, i) => ({ name: `10.0.0.${i}` })),
  links: [],
  categories: [{ name: 'c' }],
})

const cases = [
  {
    name: 'NetworkGraph',
    mountIt: () =>
      mount(NetworkGraph, {
        propsData: { graphData: graph(1) },
        stubs: { 'v-container': { template: '<div id="chart-container"><slot /></div>' } },
        attachTo: document.body,
      }),
    update: (w) => w.setProps({ graphData: graph(2) }),
  },
  {
    name: 'ModularityChart',
    mountIt: () =>
      mount(ModularityChart, {
        propsData: { modularityData: [{ k: 2, modularity: 0.1 }] },
        stubs: ['v-container', 'v-card', 'v-card-title', 'v-card-text'],
      }),
    update: (w) => w.setProps({ modularityData: [{ k: 3, modularity: 0.2 }] }),
  },
  {
    name: 'PieChart',
    mountIt: () =>
      mount(PieChart, {
        propsData: { chartData: [{ name: 'a', value: 1 }] },
        stubs: { 'v-container': { template: '<div><slot /></div>' } },
      }),
    update: (w) => w.setProps({ chartData: [{ name: 'b', value: 2 }] }),
  },
]

describe.each(cases)('$name lifecycle', ({ mountIt, update }) => {
  test('re-renders reuse one chart and one resize listener', async () => {
    const wrapper = mountIt()
    await update(wrapper)
    await wrapper.vm.$nextTick()

    expect(echarts.init).toHaveBeenCalledTimes(1)
    expect(chart.setOption.mock.calls.length).toBeGreaterThanOrEqual(2)
    expect(resizeCalls(added)).toHaveLength(1)
    wrapper.destroy()
  })

  test('destroying removes the listener it added and disposes the chart', () => {
    const wrapper = mountIt()
    const [[, listener]] = resizeCalls(added)

    wrapper.destroy()

    expect(resizeCalls(removed)).toEqual([['resize', listener]])
    expect(chart.dispose).toHaveBeenCalledTimes(1)
  })

  test('a window resize resizes the chart', () => {
    const wrapper = mountIt()
    window.dispatchEvent(new Event('resize'))
    expect(chart.resize).toHaveBeenCalled()
    wrapper.destroy()
  })
})
