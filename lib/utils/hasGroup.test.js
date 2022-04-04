const hasGroup = require('./hasGroup')

test('hasGroup function returns false if called with faulty parameters', () => {
  expect(hasGroup(1, 2)).toBe(false)
})

test('hasGroup function returns true if called with correct parameters', () => {
  const oidcUser = { memberOf: ['group1', 'group2', 'group3'] }
  expect(hasGroup('group2', oidcUser)).toBe(true)
})
