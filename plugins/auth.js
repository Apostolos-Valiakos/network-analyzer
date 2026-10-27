// Rehydrate auth state from localStorage on every page load (SPA mode).
export default ({ store }) => {
  if (!process.client) return
  const token = localStorage.getItem('auth_token')
  const isAdmin = localStorage.getItem('auth_is_admin') === 'true'
  const username = localStorage.getItem('auth_username') || null
  if (token) {
    store.commit('auth/SET', { token, isAdmin, username })
  }
}
