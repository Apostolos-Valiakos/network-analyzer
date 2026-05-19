export default ({ store, redirect, route }) => {
  if (route.path === '/login') return
  if (!store.state.auth.token) {
    return redirect('/login')
  }
}
