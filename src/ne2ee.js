const crypto = require('crypto')
const JSEncrypt = require('node-jsencrypt');

class NE2EE {
    constructor({ selfPrivateKey, otherPublicKey, aesKey = Buffer.from() }) {
        this.privateKey = selfPrivateKey;
        this.publicKey = otherPublicKey;
        this.aesKey = aesKey
    }

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

exports.NE2EE = NE2EE