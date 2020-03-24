const Aesjs = require('aes-js')
const crypto = require('crypto')

function Aes (password1, password2) {
  const hash = crypto.createHash('sha256')
  hash.update(password2)
  const salt = hash.digest().toString('hex')

  const key = crypto.pbkdf2Sync(password1, salt, 10000, 48, 'sha512')
  this.key = key.subarray(0, 32)
  this.iv = key.subarray(32)
}

Aes.prototype.encrypt = function (message) {
  while (message.length % 16 !== 0) {
    message = message.concat('\u0000')
  }
  const CBC = Aesjs.ModeOfOperation.cbc
  const aes = new CBC(this.key, this.iv)
  const bytes = Aesjs.utils.utf8.toBytes(message)
  const cipher = aes.encrypt(bytes)
  return Aesjs.utils.hex.fromBytes(cipher).toString()
}

Aes.prototype.decrypt = function (cipher) {
  const CBC = Aesjs.ModeOfOperation.cbc
  const cBytes = Aesjs.utils.hex.toBytes(cipher)
  const aes = new CBC(this.key, this.iv)
  const bytes = aes.decrypt(cBytes)
  const message = Aesjs.utils.utf8.fromBytes(bytes).toString()
  return (message)
}

module.exports = Aes
