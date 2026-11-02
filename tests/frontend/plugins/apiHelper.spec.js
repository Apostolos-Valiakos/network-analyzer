/** Tests for the $api helper injected by plugins/api.js. */
import apiPlugin from '~/plugins/api'

function buildApi() {
  const injected = {}
  const context = {
    store: { state: { auth: { token: 'tok' } }, commit: jest.fn() },
    app: { router: { push: jest.fn() } },
  }
  apiPlugin(context, (name, value) => {
    injected[name] = value
  })
  return { api: injected.api, context }
}

function mockFetch(status, body, { invalidJson = false } = {}) {
  global.fetch = jest.fn().mockResolvedValue({
    status,
    ok: status >= 200 && status < 300,
    json: () => (invalidJson ? Promise.reject(new Error('not json')) : Promise.resolve(body)),
  })
}

describe('$api.url', () => {
  it('prefixes the path with the configured backend address', () => {
    const { api } = buildApi()
    expect(api.url('/v1/history/pcaps')).toBe('http://localhost:5555/v1/history/pcaps')
    expect(api.baseUrl).toBe('http://localhost:5555')
  })
})

describe('$api.json', () => {
  it('returns the parsed body and sends the login token', async () => {
    mockFetch(200, { a: 1 })
    const { api } = buildApi()
    await expect(api.json('/x')).resolves.toEqual({ a: 1 })
    const [url, options] = global.fetch.mock.calls[0]
    expect(url).toBe('http://localhost:5555/x')
    expect(options.headers.Authorization).toBe('Bearer tok')
  })

  it('throws the backend error message', async () => {
    mockFetch(404, { error: 'No results stored' })
    await expect(buildApi().api.json('/x')).rejects.toThrow('No results stored')
  })

  it('falls back to the message field', async () => {
    mockFetch(500, { message: 'Pipeline failed' })
    await expect(buildApi().api.json('/x')).rejects.toThrow('Pipeline failed')
  })

  it('reports the status when the error body is not JSON', async () => {
    mockFetch(502, null, { invalidJson: true })
    await expect(buildApi().api.json('/x')).rejects.toThrow('Request failed (502)')
  })

  it('goes through the 401 handling of $apiFetch', async () => {
    mockFetch(401, {})
    const { api, context } = buildApi()
    await expect(api.json('/x')).rejects.toThrow('Session expired')
    expect(context.app.router.push).toHaveBeenCalledWith('/login')
  })
})
