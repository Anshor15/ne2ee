# ne2ee
 
This is node js module use for simple end to end encryption. This code use simple combination of AES and RSA algorithm.

For Flutter version you can look [here](https://github.com/Anshor15/fe2ee).

# Example

```javascript
const ne2ee = require('ne2ee')

var key = ne2ee.generateKey()

var e2ee = new ne2ee.NE2EE({
    selfPrivateKey: key.rsaKeyPair.privateKey,
    otherPublicKey: key.rsaKeyPair.publicKey,
    aesKey: key.aesKey
})

var data = "very secret data";

var encrypted = e2ee.encrypt(data)

console.log(encrypted)

var decrypted = e2ee.decrypt(encrypted)

console.log(decrypted)
```