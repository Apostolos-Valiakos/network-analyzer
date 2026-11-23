/**
 * Unit tests for store/auth.js
 *
 * Tests the Vuex module in isolation — no component mounting needed.
 */

import { state as makeState, mutations, getters } from '~/store/auth'

// ── Helpers ────────────────────────────────────────────────────────────────

function freshState() {
  return makeState()
}

// ── Initial state ──────────────────────────────────────────────────────────

describe('auth store — initial state', () => {
  it('token is null', () => {
    expect(freshState().token).toBeNull()
  })

  it('isAdmin is false', () => {
    expect(freshState().isAdmin).toBe(false)
  })

  it('username is null', () => {
    expect(freshState().username).toBeNull()
  })
})

// ── SET mutation ───────────────────────────────────────────────────────────

describe('auth/SET mutation', () => {
  it('sets token', () => {
    const s = freshState()
    mutations.SET(s, { token: 'jwt-abc', isAdmin: false, username: 'alice' })
    expect(s.token).toBe('jwt-abc')
  })

  it('sets isAdmin to true', () => {
    const s = freshState()
    mutations.SET(s, { token: 't', isAdmin: true, username: 'admin' })
    expect(s.isAdmin).toBe(true)
  })

  it('sets username', () => {
    const s = freshState()
    mutations.SET(s, { token: 't', isAdmin: false, username: 'bob' })
    expect(s.username).toBe('bob')
  })

  it('defaults isAdmin to false when undefined', () => {
    const s = freshState()
    mutations.SET(s, { token: 't', username: 'carol' })
    expect(s.isAdmin).toBe(false)
  })

  it('defaults username to null when undefined', () => {
    const s = freshState()
    mutations.SET(s, { token: 't', isAdmin: false })
    expect(s.username).toBeNull()
  })

  it('overwrites previous values on repeated call', () => {
    const s = freshState()
    mutations.SET(s, { token: 'first', isAdmin: false, username: 'u1' })
    mutations.SET(s, { token: 'second', isAdmin: true, username: 'u2' })
    expect(s.token).toBe('second')
    expect(s.username).toBe('u2')
    expect(s.isAdmin).toBe(true)
  })
})

// ── CLEAR mutation ─────────────────────────────────────────────────────────

describe('auth/CLEAR mutation', () => {
  it('resets token to null', () => {
    const s = freshState()
    mutations.SET(s, { token: 'jwt-xyz', isAdmin: true, username: 'admin' })
    mutations.CLEAR(s)
    expect(s.token).toBeNull()
  })

  it('resets isAdmin to false', () => {
    const s = freshState()
    mutations.SET(s, { token: 'jwt-xyz', isAdmin: true, username: 'admin' })
    mutations.CLEAR(s)
    expect(s.isAdmin).toBe(false)
  })

  it('resets username to null', () => {
    const s = freshState()
    mutations.SET(s, { token: 'jwt-xyz', isAdmin: false, username: 'alice' })
    mutations.CLEAR(s)
    expect(s.username).toBeNull()
  })

  it('is idempotent — calling CLEAR twice does not throw', () => {
    const s = freshState()
    expect(() => {
      mutations.CLEAR(s)
      mutations.CLEAR(s)
    }).not.toThrow()
  })
})

// ── loggedIn getter ────────────────────────────────────────────────────────

describe('auth/loggedIn getter', () => {
  it('returns false when token is null', () => {
    const s = freshState()
    expect(getters.loggedIn(s)).toBe(false)
  })

  it('returns false when token is empty string', () => {
    const s = { ...freshState(), token: '' }
    expect(getters.loggedIn(s)).toBe(false)
  })

  it('returns true when token is set', () => {
    const s = { ...freshState(), token: 'some-jwt-token' }
    expect(getters.loggedIn(s)).toBe(true)
  })

  it('reflects state after SET', () => {
    const s = freshState()
    expect(getters.loggedIn(s)).toBe(false)
    mutations.SET(s, { token: 'jwt', isAdmin: false, username: 'u' })
    expect(getters.loggedIn(s)).toBe(true)
  })

  it('reflects state after CLEAR', () => {
    const s = freshState()
    mutations.SET(s, { token: 'jwt', isAdmin: false, username: 'u' })
    mutations.CLEAR(s)
    expect(getters.loggedIn(s)).toBe(false)
  })
})
