/**
 * Lifecycle tests for the monitoring dashboard: charts are created when they
 * appear, and everything is released when the page is left.
 */
import { shallowMount } from '@vue/test-utils'
import * as echarts from 'echarts'
import { io } from 'socket.io-client'
import EChart from '~/components/monitoring/EChart.vue'
import MonitoringCharts from '~/components/monitoring/MonitoringCharts.vue'
import ContinuousMonitoring from '~/pages/continuous_monitoring.vue'

jest.mock('echarts', () => ({ init: jest.fn() }))
jest.mock('socket.io-client', () => ({ io: jest.fn() }))

const chartInstance = () => ({ setOption: jest.fn(), resize: jest.fn(), dispose: jest.fn() })
const flow = { ts: 100, 'id.orig_h': 'a', 'id.resp_h': 'b', proto: 'tcp', conn_state: 'SF', orig_bytes: 1, resp_bytes: 1 }

describe('EChart', () => {
  let chart

  beforeEach(() => {
    chart = chartInstance()
    echarts.init.mockReset().mockReturnValue(chart)
  })

  const mountChart = (props = {}) =>
    shallowMount(EChart, { propsData: { chartId: 'c', height: 100, option: { a: 1 }, ...props } })

  it('creates the chart and draws as soon as it is mounted', () => {
    const wrapper = mountChart()
    expect(echarts.init).toHaveBeenCalledWith(wrapper.element)
    expect(chart.setOption).toHaveBeenCalledWith({ a: 1 }, false)
    expect(wrapper.attributes('id')).toBe('c')
  })

  it('redraws when the option changes', async () => {
    const wrapper = mountChart()
    await wrapper.setProps({ option: { a: 2 } })
    expect(chart.setOption).toHaveBeenLastCalledWith({ a: 2 }, false)
  })

  it('can replace the option instead of merging', () => {
    mountChart({ replace: true })
    expect(chart.setOption).toHaveBeenCalledWith({ a: 1 }, true)
  })

  it('follows window resizes until destroyed, then disposes the chart', () => {
    const wrapper = mountChart()
    window.dispatchEvent(new Event('resize'))
    expect(chart.resize).toHaveBeenCalledTimes(1)
    wrapper.destroy()
    expect(chart.dispose).toHaveBeenCalledTimes(1)
    window.dispatchEvent(new Event('resize'))
    expect(chart.resize).toHaveBeenCalledTimes(1)
  })
})

describe('MonitoringCharts topology refresh', () => {
  beforeEach(() => jest.useFakeTimers())
  afterEach(() => jest.useRealTimers())

  const mountCharts = (live) =>
    shallowMount(MonitoringCharts, { propsData: { stats: [flow], live }, stubs: ['v-row', 'v-col', 'v-card'] })

  it('has the topology ready immediately', () => {
    const { conversations } = mountCharts(true).vm
    expect(conversations.series[0].links).toHaveLength(1)
  })

  it('takes new flows on the 60 s timer, not with each batch', async () => {
    const wrapper = mountCharts(true)
    const initial = wrapper.vm.conversations
    await wrapper.setProps({ stats: [flow, { ...flow, 'id.orig_h': 'c' }] })
    expect(wrapper.vm.conversations).toBe(initial)
    jest.advanceTimersByTime(60000)
    expect(wrapper.vm.conversations.series[0].links).toHaveLength(2)
  })

  it('does not refresh outside live mode', async () => {
    const wrapper = mountCharts(false)
    const initial = wrapper.vm.conversations
    await wrapper.setProps({ stats: [flow, { ...flow, 'id.orig_h': 'c' }] })
    jest.advanceTimersByTime(60000)
    expect(wrapper.vm.conversations).toBe(initial)
  })

  it('stops the timer when destroyed', () => {
    const wrapper = mountCharts(true)
    wrapper.destroy()
    expect(jest.getTimerCount()).toBe(0)
  })
})

describe('continuous_monitoring page', () => {
  let socket
  let handlers

  beforeEach(() => {
    handlers = {}
    socket = { on: jest.fn((name, fn) => { handlers[name] = fn }), disconnect: jest.fn() }
    io.mockReset().mockReturnValue(socket)
  })

  function mountPage(body = [flow]) {
    return shallowMount(ContinuousMonitoring, {
      mocks: {
        $apiFetch: jest.fn().mockResolvedValue({ ok: true, json: async () => body }),
        $api: { baseUrl: 'http://api', url: (p) => `http://api${p}` },
      },
      stubs: ['v-container', 'v-snackbar', 'v-row', 'v-col', 'v-card', 'v-icon', 'v-text-field', 'v-switch', 'v-btn'],
    })
  }

  it('connects to the configured backend and loads statistics', async () => {
    const wrapper = mountPage()
    await new Promise((resolve) => setTimeout(resolve))
    expect(io.mock.calls[0][0]).toBe('http://api')
    expect(wrapper.vm.$apiFetch.mock.calls[0][0]).toMatch(/^http:\/\/api\/v1\/network\/statistics\?start_time=/)
    expect(wrapper.vm.stats).toEqual([flow])
    expect(wrapper.vm.loading).toBe(false)
  })

  it('disconnects the live feed when the page is left', () => {
    const wrapper = mountPage()
    wrapper.destroy()
    expect(socket.disconnect).toHaveBeenCalledTimes(1)
  })

  it('adds live flows only in live mode', async () => {
    const wrapper = mountPage([])
    await new Promise((resolve) => setTimeout(resolve))
    handlers.new_network_data([flow])
    expect(wrapper.vm.stats).toHaveLength(1)
    wrapper.vm.isLive = false
    handlers.new_network_data([flow])
    expect(wrapper.vm.stats).toHaveLength(1)
  })

  it('shows an error when statistics cannot be loaded', async () => {
    const wrapper = mountPage()
    wrapper.vm.$apiFetch.mockResolvedValue({ ok: false })
    await wrapper.vm.fetchStatistics()
    expect(wrapper.vm.snackbarText).toBe('Could not load stats.')
    expect(wrapper.vm.snackbarType).toBe('error')
  })
})
