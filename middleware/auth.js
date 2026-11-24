// Every page needs a login except /login itself. A trailing slash ("/login/")
// is the same page: comparing the raw path made it redirect to itself forever.
export default ({ store, redirect, route }) => {
  const path = route.path.replace(/\/+$/, '') || '/'
  if (path === '/login') return
  if (!store.state.auth.token) {
    return redirect('/login')
  }
}
