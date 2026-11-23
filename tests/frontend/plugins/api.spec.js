/**
 * Unit tests for plugins/api.js (the $apiFetch plugin).
 *
 * The plugin is a Nuxt plugin factory that accepts a context object and
 * calls inject('apiFetch', fn). We test the injected fn directly.
 */

import apiPlugin from '~/plugins/api'

// ── Helpers ────────────────────────────────────────────────────────────────

function buildContext({ token = null, router = null } = {}) {
  const committed = []
  const store = {
    state: { auth: { token } },
    commit: jest.fn((type, payload) => committed.push({ type, payload })),
    _committed: committed,
  }
  const mockRouter = router || { push: jest.fn() }
  return {
    store,
    app: { router: mockRouter },
  }
}

function buildPlugin(contextOverrides = {}) {
  const context = buildContext(contextOverrides)
  let injectedFn = null
  apiPlugin(context, (name, fn) => {
    if (name === 'apiFetch') injectedFn = fn
  })
  return { apiFetch: injectedFn, context }
}

function mockFetch(status, body = {}) {
  return jest.fn().mockResolvedValue({
    status,
    ok: status >= 200 && status < 300,
    json: () => Promise.resolve(body),
  })
}

// ── Injection ──────────────────────────────────────────────────────────────

describe('api plugin injection', () => {
  it('injects apiFetch function', () => {
    const { apiFetch } = buildPlugin()
    expect(typeof apiFetch).toBe('function')
  })
})

// ── Authorization header ───────────────────────────────────────────────────

describe('apiFetch — Authorization header', () => {
  it('adds Bearer token when auth token is present', async () => {
    global.fetch = mockFetch(200)
    const { apiFetch } = buildPlugin({ token: 'my-jwt-token' })
    await apiFetch('http://localhost:5555/some-endpoint')
    const [, options] = global.fetch.mock.calls[0]
    expect(options.headers.Authorization).toBe('Bearer my-jwt-token')
  })

  it('does NOT add Authorization header when token is null', async () => {
    global.fetch = mockFetch(200)
    const { apiFetch } = buildPlugin({ token: null })
    await apiFetch('http://localhost:5555/some-endpoint')
    const [, options] = global.fetch.mock.calls[0]
    expect(options.headers.Authorization).toBeUndefined()
  })

  it('merges caller-provided headers with auth header', async () => {
    global.fetch = mockFetch(200)
    const { apiFetch } = buildPlugin({ token: 'tok' })
    await apiFetch('http://localhost:5555/ep', {
      headers: { 'Content-Type': 'application/json' },
    })
    const [, options] = global.fetch.mock.calls[0]
    expect(options.headers['Content-Type']).toBe('application/json')
    expect(options.headers.Authorization).toBe('Bearer tok')
  })

  it('passes additional fetch options through', async () => {
    global.fetch = mockFetch(200)
    const { apiFetch } = buildPlugin({ token: null })
    await apiFetch('http://localhost:5555/ep', { method: 'POST', body: '{}' })
    const [url, options] = global.fetch.mock.calls[0]
    expect(options.method).toBe('POST')
    expect(options.body).toBe('{}')
  })
})

// ── 401 handling ───────────────────────────────────────────────────────────

describe('apiFetch — 401 handling', () => {
  it('commits auth/CLEAR on 401', async () => {
    global.fetch = mockFetch(401)
    const { apiFetch, context } = buildPlugin({ token: 'expired' })
    await expect(apiFetch('http://localhost:5555/secure')).rejects.toThrow()
    expect(context.store.commit).toHaveBeenCalledWith('auth/CLEAR')
  })

  it('redirects to /login on 401', async () => {
    global.fetch = mockFetch(401)
    const { apiFetch, context } = buildPlugin({ token: 'expired' })
    await expect(apiFetch('http://localhost:5555/secure')).rejects.toThrow()
    expect(context.app.router.push).toHaveBeenCalledWith('/login')
  })

  it('throws "Session expired" error on 401', async () => {
    global.fetch = mockFetch(401)
    const { apiFetch } = buildPlugin({ token: 'expired' })
    await expect(apiFetch('http://localhost:5555/secure')).rejects.toThrow(
      'Session expired'
    )
  })

  it('does NOT throw or redirect on 200', async () => {
    global.fetch = mockFetch(200, { data: 'ok' })
    const { apiFetch, context } = buildPlugin({ token: 'valid' })
    const res = await apiFetch('http://localhost:5555/ok')
    expect(context.store.commit).not.toHaveBeenCalled()
    expect(context.app.router.push).not.toHaveBeenCalled()
    expect(res.status).toBe(200)
  })

  it('does NOT throw or redirect on 404', async () => {
    global.fetch = mockFetch(404)
    const { apiFetch, context } = buildPlugin({ token: 'valid' })
    const res = await apiFetch('http://localhost:5555/missing')
    expect(context.store.commit).not.toHaveBeenCalled()
    expect(res.status).toBe(404)
  })
})

// ── Return value ───────────────────────────────────────────────────────────

describe('apiFetch — return value', () => {
  it('returns the Response object on success', async () => {
    const fakeResponse = { status: 200, ok: true, json: async () => ({ x: 1 }) }
    global.fetch = jest.fn().mockResolvedValue(fakeResponse)
    const { apiFetch } = buildPlugin({ token: null })
    const res = await apiFetch('http://localhost:5555/ep')
    expect(res).toBe(fakeResponse)
  })
})
