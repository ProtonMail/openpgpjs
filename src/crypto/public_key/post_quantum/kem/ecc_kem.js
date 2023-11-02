import * as ecdhX from '../../elliptic/ecdh_x';
import hash from '../../../hash';
import util from '../../../../util';
import enums from '../../../../enums';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { A, k } = await ecdhX.generate(enums.publicKey.x25519);
      return {
        eccPublicKey: A,
        eccSecretKey: k
      };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function encaps(algo, eccRecipientPublicKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
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

export async function decaps(algo, eccCipherText, eccSecretKey, eccPublicKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
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
