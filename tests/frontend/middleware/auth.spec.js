/** Tests for middleware/auth.js: every page needs a login except /login. */
import auth from '~/middleware/auth'

function run(path, token = null) {
  const redirect = jest.fn()
  auth({ store: { state: { auth: { token } } }, redirect, route: { path } })
  return redirect
}

describe('auth middleware', () => {
  test('lets the login page through without a token', () => {
    expect(run('/login')).not.toHaveBeenCalled()
  })

  test('treats /login/ as the login page (it used to redirect to itself)', () => {
    expect(run('/login/')).not.toHaveBeenCalled()
  })

  test('sends other pages to /login without a token', () => {
    expect(run('/history')).toHaveBeenCalledWith('/login')
    expect(run('/history/')).toHaveBeenCalledWith('/login')
    expect(run('/')).toHaveBeenCalledWith('/login')
  })

  test('lets logged-in users through', () => {
    expect(run('/history', 'jwt')).not.toHaveBeenCalled()
  })
})
