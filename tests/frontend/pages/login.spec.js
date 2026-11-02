/**
 * Unit tests for pages/login.vue — login() method logic.
 *
 * We mount the component with a stub store and mock global.fetch to test
 * the login flow without a real backend.
 */

import { shallowMount, createLocalVue } from '@vue/test-utils'
import Vuex from 'vuex'
import LoginPage from '~/pages/login.vue'

const localVue = createLocalVue()
localVue.use(Vuex)

// ── Helpers ────────────────────────────────────────────────────────────────

function buildStore(committed = []) {
  return new Vuex.Store({
    modules: {
      auth: {
        namespaced: true,
        state: () => ({ token: null, isAdmin: false, username: null }),
        mutations: {
          SET(state, payload) {
            committed.push({ type: 'auth/SET', payload })
            Object.assign(state, payload)
          },
        },
      },
    },
  })
}

function buildRouter(pushed = []) {
  return { push: jest.fn((path) => pushed.push(path)) }
}

function mountLogin(store, router) {
  return shallowMount(LoginPage, {
    localVue,
    store,
    mocks: {
      $store: store,
      $router: router,
    },
    stubs: { NuxtLink: true },
  })
}

function mockFetchSuccess(token = 'jwt-tok', isAdmin = false) {
  global.fetch = jest.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({ access_token: token, is_admin: isAdmin }),
  })
}

function mockFetchFailure(status = 401, errorMsg = 'Invalid credentials') {
  global.fetch = jest.fn().mockResolvedValue({
    ok: false,
    status,
    json: async () => ({ error: errorMsg }),
  })
}

// ── Initial data ───────────────────────────────────────────────────────────

describe('login page — initial state', () => {
  it('username is empty string', () => {
    const wrapper = mountLogin(buildStore(), buildRouter())
    expect(wrapper.vm.username).toBe('')
  })

  it('password is empty string', () => {
    const wrapper = mountLogin(buildStore(), buildRouter())
    expect(wrapper.vm.password).toBe('')
  })

  it('loading is false', () => {
    const wrapper = mountLogin(buildStore(), buildRouter())
    expect(wrapper.vm.loading).toBe(false)
  })

  it('error is null', () => {
    const wrapper = mountLogin(buildStore(), buildRouter())
    expect(wrapper.vm.error).toBeNull()
  })
})

// ── login() — guard conditions ─────────────────────────────────────────────

describe('login() guard conditions', () => {
  it('does nothing when username is empty', async () => {
    global.fetch = jest.fn()
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.password = 'pass'
    await wrapper.vm.login()
    expect(global.fetch).not.toHaveBeenCalled()
  })

  it('does nothing when password is empty', async () => {
    global.fetch = jest.fn()
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'alice'
    await wrapper.vm.login()
    expect(global.fetch).not.toHaveBeenCalled()
  })

  it('does nothing when both are empty', async () => {
    global.fetch = jest.fn()
    const wrapper = mountLogin(buildStore(), buildRouter())
    await wrapper.vm.login()
    expect(global.fetch).not.toHaveBeenCalled()
  })
})

// ── login() — successful login ────────────────────────────────────────────

describe('login() — successful response', () => {
  it('calls fetch with correct URL and method', async () => {
    mockFetchSuccess()
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'alice'
    wrapper.vm.password = 'password1'
    await wrapper.vm.login()
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/auth/login'),
      expect.objectContaining({ method: 'POST' })
    )
  })

  it('sends credentials as JSON in request body', async () => {
    mockFetchSuccess()
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'alice'
    wrapper.vm.password = 'password1'
    await wrapper.vm.login()
    const [, options] = global.fetch.mock.calls[0]
    const body = JSON.parse(options.body)
    expect(body.username).toBe('alice')
    expect(body.password).toBe('password1')
  })

  it('stores token in localStorage', async () => {
    mockFetchSuccess('my-token')
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'p'
    await wrapper.vm.login()
    expect(localStorage.getItem('auth_token')).toBe('my-token')
  })

  it('stores is_admin in localStorage', async () => {
    mockFetchSuccess('tok', true)
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'admin'
    wrapper.vm.password = 'pass'
    await wrapper.vm.login()
    expect(localStorage.getItem('auth_is_admin')).toBe('true')
  })

  it('commits auth/SET with token and isAdmin', async () => {
    const committed = []
    const store = buildStore(committed)
    mockFetchSuccess('my-jwt', true)
    const wrapper = mountLogin(store, buildRouter())
    wrapper.vm.username = 'admin'
    wrapper.vm.password = 'pass'
    await wrapper.vm.login()
    const call = committed.find((c) => c.type === 'auth/SET')
    expect(call).toBeDefined()
    expect(call.payload.token).toBe('my-jwt')
    expect(call.payload.isAdmin).toBe(true)
  })

  it('redirects to / after successful login', async () => {
    const pushed = []
    mockFetchSuccess()
    const wrapper = mountLogin(buildStore(), buildRouter(pushed))
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'p'
    await wrapper.vm.login()
    expect(pushed).toContain('/')
  })

  it('sets loading=false after success', async () => {
    mockFetchSuccess()
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'p'
    await wrapper.vm.login()
    expect(wrapper.vm.loading).toBe(false)
  })
})

// ── login() — failed login ────────────────────────────────────────────────

describe('login() — error response', () => {
  it('sets error message on 401', async () => {
    mockFetchFailure(401, 'Invalid credentials')
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'wrong'
    await wrapper.vm.login()
    expect(wrapper.vm.error).toBe('Invalid credentials')
  })

  it('does NOT redirect on failure', async () => {
    const pushed = []
    mockFetchFailure(401)
    const wrapper = mountLogin(buildStore(), buildRouter(pushed))
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'wrong'
    await wrapper.vm.login()
    expect(pushed).toHaveLength(0)
  })

  it('does NOT commit auth/SET on failure', async () => {
    const committed = []
    const store = buildStore(committed)
    mockFetchFailure(401)
    const wrapper = mountLogin(store, buildRouter())
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'wrong'
    await wrapper.vm.login()
    expect(committed.find((c) => c.type === 'auth/SET')).toBeUndefined()
  })

  it('sets loading=false even on failure', async () => {
    mockFetchFailure(401)
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'p'
    await wrapper.vm.login()
    expect(wrapper.vm.loading).toBe(false)
  })

  it('sets error on network failure', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('Network error'))
    const wrapper = mountLogin(buildStore(), buildRouter())
    wrapper.vm.username = 'u'
    wrapper.vm.password = 'p'
    await wrapper.vm.login()
    expect(wrapper.vm.error).toBe('Network error')
    expect(wrapper.vm.loading).toBe(false)
  })
})
