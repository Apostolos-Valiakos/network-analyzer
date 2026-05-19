export default ({ store, redirect }) => {
  if (!store.state.auth.isAdmin) {
    return redirect('/')
  }
}
