/**
 * Unit tests for components/AppHeader.vue
 *
 * Tests computed properties, navigation filtering, and methods
 * (logout, toggleTheme) in isolation from Nuxt and Vuetify internals.
 */

import { shallowMount, createLocalVue } from '@vue/test-utils'
import Vuex from 'vuex'
import AppHeader from '~/components/AppHeader.vue'

const localVue = createLocalVue()
localVue.use(Vuex)

// ── Helpers ────────────────────────────────────────────────────────────────

function buildStore({ token = null, isAdmin = false, username = null } = {}) {
  return new Vuex.Store({
    modules: {
      auth: {
        namespaced: true,
        state: () => ({ token, isAdmin, username }),
        mutations: {
          CLEAR(state) {
            state.token = null
            state.isAdmin = false
            state.username = null
          },
        },
      },
    },
  })
}

function mountHeader({ token = null, isAdmin = false, username = null, route = '/' } = {}) {
  const store = buildStore({ token, isAdmin, username })
  const committed = []
  const originalCommit = store.commit.bind(store)
  store.commit = jest.fn((type, payload) => {
    committed.push({ type, payload })
    originalCommit(type, payload)
  })
  store._committed = committed

  const vuetify = {
    theme: { dark: false },
  }
  const router = { push: jest.fn() }
  const mockRoute = { path: route }

  const wrapper = shallowMount(AppHeader, {
    localVue,
    store,
    mocks: {
      $store: store,
      $vuetify: vuetify,
      $router: router,
      $route: mockRoute,
      $api: { url: (path) => `http://localhost:5555${path}` },
    },
    stubs: {
      'v-app-bar': true,
      'v-btn': true,
      'v-icon': true,
      'v-navigation-drawer': true,
      'v-list': true,
      'v-list-item': true,
      NuxtLink: true,
    },
  })
  return { wrapper, store, router, vuetify }
}

// ── Computed: username ─────────────────────────────────────────────────────

describe('AppHeader — username computed', () => {
  it('returns null when not logged in', () => {
    const { wrapper } = mountHeader({ username: null })
    expect(wrapper.vm.username).toBeNull()
  })

  it('returns the username from store', () => {
    const { wrapper } = mountHeader({ username: 'alice', token: 'tok' })
    expect(wrapper.vm.username).toBe('alice')
  })
})

// ── Computed: isAdmin ──────────────────────────────────────────────────────

describe('AppHeader — isAdmin computed', () => {
  it('returns false for regular user', () => {
    const { wrapper } = mountHeader({ isAdmin: false })
    expect(wrapper.vm.isAdmin).toBe(false)
  })

  it('returns true for admin user', () => {
    const { wrapper } = mountHeader({ isAdmin: true })
    expect(wrapper.vm.isAdmin).toBe(true)
  })
})

// ── Computed: visibleNavItems ──────────────────────────────────────────────

describe('AppHeader — visibleNavItems computed', () => {
  it('excludes adminOnly items for regular user', () => {
    const { wrapper } = mountHeader({ isAdmin: false })
    const items = wrapper.vm.visibleNavItems
    const hasAdminItem = items.some((item) => item.adminOnly)
    expect(hasAdminItem).toBe(false)
  })

  it('includes adminOnly items for admin user', () => {
    const { wrapper } = mountHeader({ isAdmin: true })
    const items = wrapper.vm.visibleNavItems
    const adminItems = items.filter((item) => item.adminOnly)
    expect(adminItems.length).toBeGreaterThan(0)
  })

  it('always includes Home and History for any user', () => {
    const { wrapper } = mountHeader({ isAdmin: false })
    const labels = wrapper.vm.visibleNavItems.map((i) => i.label)
    expect(labels).toContain('Home')
    expect(labels).toContain('History')
  })

  it('has at least 4 nav items for any user', () => {
    const { wrapper } = mountHeader({ isAdmin: false })
    expect(wrapper.vm.visibleNavItems.length).toBeGreaterThanOrEqual(4)
  })
})

// ── isActive helper ────────────────────────────────────────────────────────

describe('AppHeader — isActive()', () => {
  it('returns true for "/" only when on home route', () => {
    const { wrapper } = mountHeader({ route: '/' })
    expect(wrapper.vm.isActive('/')).toBe(true)
  })

  it('returns false for "/" when on /analyze', () => {
    const { wrapper } = mountHeader({ route: '/analyze' })
    expect(wrapper.vm.isActive('/')).toBe(false)
  })

  it('returns true for /analyze when on /analyze', () => {
    const { wrapper } = mountHeader({ route: '/analyze' })
    expect(wrapper.vm.isActive('/analyze')).toBe(true)
  })

  it('returns true for /admin when on /admin/users', () => {
    const { wrapper } = mountHeader({ route: '/admin/users' })
    expect(wrapper.vm.isActive('/admin')).toBe(true)
  })
})

// ── toggleTheme ────────────────────────────────────────────────────────────

describe('AppHeader — toggleTheme()', () => {
  it('toggles dark to true when currently false', () => {
    const { wrapper, vuetify } = mountHeader()
    vuetify.theme.dark = false
    wrapper.vm.toggleTheme()
    expect(vuetify.theme.dark).toBe(true)
  })

  it('toggles dark to false when currently true', () => {
    const { wrapper, vuetify } = mountHeader()
    vuetify.theme.dark = true
    wrapper.vm.toggleTheme()
    expect(vuetify.theme.dark).toBe(false)
  })

  it('saves theme preference to localStorage', () => {
    const { wrapper, vuetify } = mountHeader()
    vuetify.theme.dark = false
    wrapper.vm.toggleTheme()
    expect(localStorage.getItem('theme')).toBe('dark')
  })

  it('saves "light" when switching to light mode', () => {
    const { wrapper, vuetify } = mountHeader()
    vuetify.theme.dark = true
    wrapper.vm.toggleTheme()
    expect(localStorage.getItem('theme')).toBe('light')
  })
})

// ── logout ─────────────────────────────────────────────────────────────────

describe('AppHeader — logout()', () => {
  it('commits auth/CLEAR', () => {
    const { wrapper, store } = mountHeader({ token: 'tok', username: 'alice' })
    wrapper.vm.logout()
    expect(store.commit).toHaveBeenCalledWith('auth/CLEAR')
  })

  it('removes auth_token from localStorage', () => {
    localStorage.setItem('auth_token', 'some-token')
    const { wrapper } = mountHeader({ token: 'tok' })
    wrapper.vm.logout()
    expect(localStorage.getItem('auth_token')).toBeNull()
  })

  it('removes auth_is_admin from localStorage', () => {
    localStorage.setItem('auth_is_admin', 'true')
    const { wrapper } = mountHeader({ token: 'tok' })
    wrapper.vm.logout()
    expect(localStorage.getItem('auth_is_admin')).toBeNull()
  })

  it('removes auth_username from localStorage', () => {
    localStorage.setItem('auth_username', 'alice')
    const { wrapper } = mountHeader({ token: 'tok' })
    wrapper.vm.logout()
    expect(localStorage.getItem('auth_username')).toBeNull()
  })

  it('redirects to /login', () => {
    const { wrapper, router } = mountHeader({ token: 'tok' })
    wrapper.vm.logout()
    expect(router.push).toHaveBeenCalledWith('/login')
  })
})

// ── isDark computed ────────────────────────────────────────────────────────

describe('AppHeader — isDark computed', () => {
  it('reflects vuetify.theme.dark', () => {
    const { wrapper, vuetify } = mountHeader()
    vuetify.theme.dark = true
    expect(wrapper.vm.isDark).toBe(true)
    vuetify.theme.dark = false
    expect(wrapper.vm.isDark).toBe(false)
  })
})
