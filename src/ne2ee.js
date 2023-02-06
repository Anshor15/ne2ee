const crypto = require('crypto')
const JSEncrypt = require('node-jsencrypt');

/**
 * 
 * @param {string} selfPrivateKey Private Key for decrypt data
 * @param {string} otherPublicKey Public Key for encrypt data
 * @param {Buffer} aesKey AES Key
 */
class NE2EE {
    constructor({ selfPrivateKey, otherPublicKey, aesKey }) {
        this.privateKey = selfPrivateKey;
        this.publicKey = otherPublicKey;
        this.aesKey = aesKey
    }
    /**
     * 
     * @param {string} encrypted String encrypted data
     * @returns Decrypted string data
     */
    decrypt(encrypted) {
        try {
            //#region Get RSA and AES key
            var privateKey = this.privateKey;
            const key = this.aesKey;
            //#endregion

            //#region Separate encrypted IV and Data
            var encryptedBuffer = Buffer.from(encrypted, 'base64')
            var encryptedIv = encryptedBuffer.subarray(0, 344)
            var encryptedData = encryptedBuffer.subarray(344, encryptedBuffer.length)
            //#endregion

            //#region Decrypt IV
            const crypt = new JSEncrypt();
            crypt.setPrivateKey(privateKey);
            var decryptedRsa = crypt.decrypt(encryptedIv.toString('utf8'));
            var iv = Buffer.from(decryptedRsa, 'hex')
            //#endregion

            //#region Decrypt data
            let decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
            let decrypted = decipher.update(encryptedData);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            //#endregion

            //#region Split data string and image
            // String
            var finalDecrypted = decrypted.toString();
            return finalDecrypted;
            //#endregion
        }
        catch (e) {
            console.error(e);
            throw new Error(e)
        }
    }

    /**
     * 
     * @param {string} data Encrypted data
     * @param {{algorithm: 'aes-256-cbc'}} aesAlgorithm Default is aes-256-cbc
     * @returns Base64 encrypted data
     */
    encrypt(data, aesAlgorithm = { algorithm: 'aes-256-cbc' }) {
        const publicKey = this.publicKey;
        const aesKey = this.aesKey;
        const iv = crypto.randomBytes(16);

        let cipher = crypto.createCipheriv(aesAlgorithm.algorithm, aesKey, iv);
        let encryptedData = cipher.update(data);
        encryptedData = Buffer.concat([encryptedData, cipher.final()]);

        const crypt = new JSEncrypt();
        crypt.setPublicKey(publicKey)
        var encryptedIv = crypt.encrypt(iv.toString('base64'));

        var finalEncrypted = Buffer.concat([Buffer.from(encryptedIv), encryptedData]);

        return finalEncrypted.toString('base64')
    }
}

/**
 * 
 * @param {int} aesKeySize AES key size, default is 16
 * @param {int} rsaKeyLength RSA key length, default is 2048
 * @param {'spki' | 'pkcs1'} publicKeyType Default type is 'spki'
 * @param {string} publicKeyFormat Default is 'pem'
 * @param {'pkcs1' | 'pkcs8'} privateKeyType Default is 'pkcs8'
 * @param {string} privateKeyFormat Default is 'pem'
 * @returns Object key pair
 */
function generateKey(
    aesKeySize = 16,
    rsaKeyLength = 2048,
    publicKeyType = 'spki',
    publicKeyFormat = 'pem',
    privateKeyType = 'pkcs8',
    privateKeyFormat = 'pem'
) {
    const aesKey = crypto.randomBytes(aesKeySize)
    const rsaKeyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: rsaKeyLength,
        publicKeyEncoding: {
            type: publicKeyType,
            format: publicKeyFormat,
        },
        privateKeyEncoding: {
            type: privateKeyType,
            format: privateKeyFormat
        }
    })

    const keyPair = {
        rsaKeyPair,
        aesKey
    }

    return keyPair
}

exports.NE2EE = NE2EE
exports.generateKey = generateKey