// Wraps fetch() to inject the Authorization header and handle 401 globally.
export default (context, inject) => {
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
  inject('apiFetch', apiFetch)
}
