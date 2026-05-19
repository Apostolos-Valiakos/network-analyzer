export const state = () => ({
  token: null,
  isAdmin: false,
  username: null,
})

export const mutations = {
  SET(state, { token, isAdmin, username }) {
    state.token = token
    state.isAdmin = isAdmin ?? false
    state.username = username ?? null
  },
  CLEAR(state) {
    state.token = null
    state.isAdmin = false
    state.username = null
  },
}

export const getters = {
  loggedIn: (state) => !!state.token,
}
