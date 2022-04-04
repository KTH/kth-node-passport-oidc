const { encrypt, decrypt } = require('./crypto')

test('test correct encryption and decryption', () => {
  const secretKey = 'santaIsReal39432santaIsReal39432'
  const text = 'Bacon ipsum dolor amet beef landjaeger sausage'

  const encrypted = encrypt(text, secretKey)

  expect(encrypted).toEqual(
    expect.objectContaining({
      content: expect.any(String),
      iv: expect.any(String),
    })
  )

  const decrypted = decrypt(encrypted, secretKey)

  expect(decrypted).toMatch(text)
})

test('throw error when no secret key is supplied', () => {
  const text = 'Bacon ipsum dolor amet beef landjaeger sausage'
  expect(() => encrypt(text)).toThrow()
  expect(() => encrypt(text, '')).toThrow()
})
