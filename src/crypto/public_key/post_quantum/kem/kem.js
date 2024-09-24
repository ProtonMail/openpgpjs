import * as eccKem from './ecc_kem';
import * as mlKem from './ml_kem';
import * as aesKW from '../../../aes_kw';
import util from '../../../../util';
import enums from '../../../../enums';
import hash from '../../../hash';

export async function generate(algo) {
  const { eccPublicKey, eccSecretKey } = await eccKem.generate(algo);
  const { mlkemPublicKey, mlkemSecretKey } = await mlKem.generate(algo);

  return { eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSecretKey };
}

export async function encrypt(algo, eccPublicKey, mlkemPublicKey, sessioneKeyData) {
  const { eccKeyShare, eccCipherText } = await eccKem.encaps(algo, eccPublicKey);
  const { mlkemKeyShare, mlkemCipherText } = await mlKem.encaps(algo, mlkemPublicKey);
  const kek = await multiKeyCombine(algo, eccKeyShare, eccCipherText, eccPublicKey, mlkemKeyShare, mlkemCipherText, mlkemPublicKey);
  const wrappedKey = await aesKW.wrap(enums.symmetric.aes256, kek, sessioneKeyData); // C
  return { eccCipherText, mlkemCipherText, wrappedKey };
}

export async function decrypt(algo, eccCipherText, mlkemCipherText, eccSecretKey, eccPublicKey, mlkemSecretKey, mlkemPublicKey, encryptedSessionKeyData) {
  const eccKeyShare = await eccKem.decaps(algo, eccCipherText, eccSecretKey, eccPublicKey);
  const mlkemKeyShare = await mlKem.decaps(algo, mlkemCipherText, mlkemSecretKey);
  const kek = await multiKeyCombine(algo, eccKeyShare, eccCipherText, eccPublicKey, mlkemKeyShare, mlkemCipherText, mlkemPublicKey);
  const sessionKey = await aesKW.unwrap(enums.symmetric.aes256, kek, encryptedSessionKeyData);
  return sessionKey;
}

async function multiKeyCombine(algo, ecdhKeyShare, ecdhCipherText, ecdhPublicKey, mlkemKeyShare, mlkemCipherText, mlkemPublicKey) {
  const encData = util.concatUint8Array([
    // counter
    new Uint8Array([0, 0, 0, 1]),
    // eccData
    ecdhKeyShare,
    ecdhCipherText,
    ecdhPublicKey,
    // mlkemData
    mlkemKeyShare,
    mlkemCipherText,
    mlkemPublicKey,
    // fixedInfo
    new Uint8Array([algo]),
    util.encodeUTF8('OpenPGPCompositeKDFv1') // domSeparation
  ]);

  const kek = await hash.digest(enums.hash.sha3_256, encData);
  return kek;
}

export async function validateParams(algo, eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSecretKey) {
  const eccValidationPromise = eccKem.validateParams(algo, eccPublicKey, eccSecretKey);
  const mlkemValidationPromise = mlKem.validateParams(algo, mlkemPublicKey, mlkemSecretKey);
  const valid = await eccValidationPromise && await mlkemValidationPromise;
  return valid;
}
