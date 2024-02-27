import * as eccKem from './ecc_kem';
import * as mlKem from './ml_kem';
import * as aesKW from '../../../aes_kw';
import util from '../../../../util';
import enums from '../../../../enums';

export async function generate(algo) {
  const { eccPublicKey, eccSecretKey } = await eccKem.generate(algo);
  const { mlkemPublicKey, mlkemSecretKey } = await mlKem.generate(algo);

  return { eccPublicKey, eccSecretKey, mlkemPublicKey, mlkemSecretKey };
}

export async function encrypt(algo, eccPublicKey, mlkemPublicKey, sessioneKeyData) {
  const { eccKeyShare, eccCipherText } = await eccKem.encaps(algo, eccPublicKey);
  const { mlkemKeyShare, mlkemCipherText } = await mlKem.encaps(algo, mlkemPublicKey);
  const fixedInfo = new Uint8Array([algo]);
  const kek = await multiKeyCombine(eccKeyShare, eccCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo, 256);
  const wrappedKey = await aesKW.wrap(enums.symmetric.aes256, kek, sessioneKeyData); // C
  return { eccCipherText, mlkemCipherText, wrappedKey };
}

export async function decrypt(algo, eccCipherText, mlkemCipherText, eccSecretKey, eccPublicKey, mlkemSecretKey, encryptedSessionKeyData) {
  const eccKeyShare = await eccKem.decaps(algo, eccCipherText, eccSecretKey, eccPublicKey);
  const mlkemKeyShare = await mlKem.decaps(algo, mlkemCipherText, mlkemSecretKey);
  const fixedInfo = new Uint8Array([algo]);
  const kek = await multiKeyCombine(eccKeyShare, eccCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo, 256);
  const sessionKey = await aesKW.unwrap(enums.symmetric.aes256, kek, encryptedSessionKeyData);
  return sessionKey;
}

async function multiKeyCombine(eccKeyShare, eccCipherText, mlkemKeyShare, mlkemCipherText, fixedInfo, outputBits) {
  //   multiKeyCombine(eccKeyShare, eccCipherText,
  //                   mlkemKeyShare, mlkemCipherText,
  //                   fixedInfo, oBits)
  //
  //   Input:
  //   eccKeyShare     - the ECC key share encoded as an octet string
  //   eccCipherText   - the ECC ciphertext encoded as an octet string
  //   mlkemKeyShare   - the ML-KEM key share encoded as an octet string
  //   mlkemCipherText - the ML-KEM ciphertext encoded as an octet string
  //   fixedInfo       - the fixed information octet string
  //   oBits           - the size of the output keying material in bits
  //
  //   Constants:
  //   domSeparation       - the UTF-8 encoding of the string
  //                         "OpenPGPCompositeKeyDerivationFunction"
  //   counter             - the fixed 4 byte value 0x00000001
  //   customizationString - the UTF-8 encoding of the string "KDF"
  if (outputBits !== 256) {
    throw new Error('Unsupported output size');
  }
  const { kmac256 } = await import('@noble/hashes/sha3-addons');
  // const { eccKeyShare, eccCiphertext } = await publicKey.pqc.kem.ecdhX(keyAlgo, publicParams.A);
  // const { keyShare: mlkemKeyShare, cipherText: mlkemCipherText } = await publicKey.pqc.kem.ml(keyAlgo, publicParams.publicKey);
  const eccData = util.concatUint8Array([eccKeyShare, eccCipherText]); // eccKeyShare || eccCipherText
  const mlkemData = util.concatUint8Array([mlkemKeyShare, mlkemCipherText]); //mlkemKeyShare || mlkemCipherText
  // const fixedInfo = new Uint8Array([keyAlgo]);
  const encData = util.concatUint8Array([
    new Uint8Array([0, 0, 0, 1]),
    eccData,
    mlkemData,
    fixedInfo
  ]); // counter || eccData || mlkemData || fixedInfo

  const mb = kmac256(
    util.encodeUTF8('OpenPGPCompositeKeyDerivationFunction'),
    encData,
    { personalization: util.encodeUTF8('KDF') }
  );

  return mb;
}
