import * as ecdhX from '../elliptic/ecdh_x';
import hash from '../../hash';
import util from '../../../util';
import enums from '../../../enums';

export async function encaps(eccAlgo, eccRecipientPublicKey) {
  switch (eccAlgo) {
    case enums.publicKey.kem_x25519: {
      const { ephemeralPublicKey: eccCipherText, ephemeralSecretKey } = await ecdhX.generateEphemeralKeyPair(enums.publicKey.x25519);
      const X = await ecdhX.getSharedSecret(enums.publicKey.x25519, ephemeralSecretKey, eccRecipientPublicKey);
      const eccKeyShare = await hash.sha3_256(util.concatUint8Array([
        X,
        eccCipherText,
        eccRecipientPublicKey
      ]));
      return {
        eccCipherText,
        eccKeyShare
      };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function decaps(eccAlgo, eccCipherText, eccSecretKey, eccPublicKey) {
  switch (eccAlgo) {
    case enums.publicKey.kem_x25519: {
      const X = await ecdhX.getSharedSecret(enums.publicKey.x25519, eccSecretKey, eccCipherText);
      const eccKeyShare = await hash.sha3_256(util.concatUint8Array([
        X,
        eccCipherText,
        eccPublicKey
      ]));
      return eccKeyShare;
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}
