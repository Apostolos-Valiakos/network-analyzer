/** components/monitoring/ScanPanel.vue: failed result polls are shown, a
 *  passing failure is retried, and three in a row end the scan as failed. */
import { shallowMount } from '@vue/test-utils'
import ScanPanel from '~/components/monitoring/ScanPanel.vue'

const POLL_MS = 30000

function mountPanel(json) {
  return shallowMount(ScanPanel, {
    propsData: { analyzedIps: ['10.0.0.1'] },
    mocks: { $api: { json } },
  })
}

async function tick() {
  jest.advanceTimersByTime(POLL_MS)
  await Promise.resolve()
  await Promise.resolve()
}

beforeEach(() => jest.useFakeTimers())
afterEach(() => jest.useRealTimers())

describe('ScanPanel result polling', () => {
  test('a failed poll is shown and the next good one clears it', async () => {
    const json = jest
      .fn()
      .mockResolvedValueOnce({}) // /v1/scan/start
      .mockRejectedValueOnce(new Error('Network down'))
      .mockResolvedValueOnce({ status: 'running' })
    const wrapper = mountPanel(json)
    await wrapper.vm.start()

    await tick()
    expect(wrapper.vm.error).toBe('Could not get the scan results (retrying): Network down')
    expect(wrapper.vm.status).toBe('running')

    await tick()
    expect(wrapper.vm.error).toBeNull()
    wrapper.destroy()
  })

  test('three failed polls in a row end the scan as failed', async () => {
    const json = jest.fn().mockResolvedValueOnce({}).mockRejectedValue(new Error('Server error (500)'))
    const wrapper = mountPanel(json)
    await wrapper.vm.start()

    await tick()
    await tick()
    await tick()
    expect(wrapper.vm.status).toBe('failed')
    expect(wrapper.vm.error).toBe('Could not get the scan results: Server error (500)')

    await tick()
    expect(json).toHaveBeenCalledTimes(4) // start + 3 polls, then polling stops
    wrapper.destroy()
  })
})
