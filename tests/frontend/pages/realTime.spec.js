/**
 * pages/realTime.vue: the WebSocket to publisher.py must not outlive the page.
 * Before the fix the socket stayed open after navigating away and every
 * received packet kept being uploaded to /save-pcap.
 */

import { shallowMount } from '@vue/test-utils'
import RealTimePage from '~/pages/realTime.vue'

class FakeSocket {
  constructor(url) {
    this.url = url
    this.readyState = FakeSocket.OPEN
    this.sent = []
    this.closed = false
    FakeSocket.instances.push(this)
  }
  send(data) {
    this.sent.push(data)
  }
  close() {
    this.closed = true
  }
}
FakeSocket.OPEN = 1
FakeSocket.instances = []

function mountPage() {
  const api = { json: jest.fn().mockResolvedValue({}), url: (p) => p }
  const wrapper = shallowMount(RealTimePage, {
    mocks: { $api: api, $router: { push: jest.fn() } },
    stubs: ['v-snackbar', 'v-btn', 'v-row', 'v-col'],
  })
  return { wrapper, api }
}

function deliver(socket, msg) {
  socket.onmessage({ data: JSON.stringify(msg) })
}

beforeEach(() => {
  FakeSocket.instances = []
  global.WebSocket = FakeSocket
})

describe('realTime.vue socket lifecycle', () => {
  test('leaving the page closes the socket and detaches its handlers', () => {
    const { wrapper } = mountPage()
    wrapper.vm.connect()
    const socket = FakeSocket.instances[0]

    wrapper.destroy()

    expect(socket.closed).toBe(true)
    expect(socket.onmessage).toBeNull()
  })

  test('packets queued when leaving are saved once, as a non-final chunk', async () => {
    const { wrapper, api } = mountPage()
    wrapper.vm.connect()
    wrapper.vm.startCapture()
    deliver(FakeSocket.instances[0], { type: 'PACKET_DATA', packet: 'AAAA' })

    wrapper.destroy()
    await Promise.resolve()

    expect(api.json).toHaveBeenCalledTimes(1)
    const body = JSON.parse(api.json.mock.calls[0][1].body)
    expect(body.packets).toEqual(['AAAA'])
    expect(body.is_final_chunk).toBe(false)
  })

  test('nothing is uploaded on leave when the queue is empty', () => {
    const { wrapper, api } = mountPage()
    wrapper.vm.connect()
    wrapper.destroy()
    expect(api.json).not.toHaveBeenCalled()
  })

  test('reconnecting replaces the old socket, which then delivers nothing', () => {
    const { wrapper } = mountPage()
    wrapper.vm.connect()
    const first = FakeSocket.instances[0]
    wrapper.vm.connect()

    expect(first.closed).toBe(true)
    expect(first.onmessage).toBeNull()
    expect(FakeSocket.instances).toHaveLength(2)
  })

  test('a socket closed by the server marks the page disconnected', () => {
    const { wrapper } = mountPage()
    wrapper.vm.connect()
    const socket = FakeSocket.instances[0]
    socket.onopen()
    deliver(socket, { type: 'STATUS', status: 'CAPTURE_STARTED' })

    socket.onclose()

    expect(wrapper.vm.isConnected).toBe(false)
    expect(wrapper.vm.isCapturing).toBe(false)
  })
})
