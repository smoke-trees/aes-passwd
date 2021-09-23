declare class Aes {
  /**
   * Returns an object which can be used to encrypt and decrypt data
   * @param password1 Password 1
   * @param password2 Password 2
   */
  constructor(password1: string, password2: string);

  /**
   * Encrypts the data
   * @param data Data to be encrypted
   * @returns Encrypted data
   */
  encrypt(data: string): string;
  /**
   * Decrypt the encrypted data
   * @param encryptedString Encrypted Data to be decrypted
   * @returns Decrypted data
   */
  decrypt(encryptedString: string): string;
}

export default Aes
