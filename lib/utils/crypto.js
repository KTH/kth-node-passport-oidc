const crypto = require('crypto')

const algorithm = 'aes-256-ctr'
const iv = crypto.randomBytes(16)

const encrypt = (text, secretKey) => {
  const cipher = crypto.createCipheriv(algorithm, generateKeyFromSecret(secretKey), iv)

  const encrypted = Buffer.concat([cipher.update(text), cipher.final()])

  return {
    iv: iv.toString('hex'),
    content: encrypted.toString('hex'),
  }
}

const decrypt = (hash, secretKey) => {
  const decipher = crypto.createDecipheriv(algorithm, generateKeyFromSecret(secretKey), Buffer.from(hash.iv, 'hex'))

  const decrypted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'hex')), decipher.final()])

  return decrypted.toString()
}

const generateKeyFromSecret = secret => {
  if (!secret) throw new Error('KTH-Node-passport-oidc: No secret key was supplied to crypto functions')

  return crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32)
}

module.exports = {
  encrypt,
  decrypt,
}
