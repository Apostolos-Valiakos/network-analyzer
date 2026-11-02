// $apiFetch wraps fetch() to inject the Authorization header and handle 401 globally.
// $api holds the backend's address and a JSON helper built on $apiFetch.
export default (context, inject) => {
  const baseUrl = process.env.API_BASE_URL // default set once in nuxt.config.js

  const apiFetch = async (url, options = {}) => {
    const token = context.store.state.auth.token
    const headers = {
      ...(options.headers || {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    }
    const res = await fetch(url, { ...options, headers })
    if (res.status === 401) {
      context.store.commit('auth/CLEAR')
      if (process.client) {
        localStorage.removeItem('auth_token')
        localStorage.removeItem('auth_is_admin')
        localStorage.removeItem('auth_username')
      }
      context.app.router.push('/login')
      throw new Error('Session expired. Please log in again.')
    }
    return res
  }

  const url = (path) => `${baseUrl}${path}`

  // JSON request that throws the backend's own error message on failure.
  const json = async (path, options = {}) => {
    const res = await apiFetch(url(path), options)
    const body = await res.json().catch(() => ({}))
    if (!res.ok) {
      throw new Error(body.error || body.message || `Request failed (${res.status})`)
    }
    return body
  }

  inject('apiFetch', apiFetch)
  inject('api', { baseUrl, url, json })
}
