import enums from '../../../../enums';
import * as mldsa from './ml_dsa';
import * as eccdsa from './ecc_dsa';
import { getHashByteLength } from '../../../hash';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { eccSecretKey, eccPublicKey } = await eccdsa.generate(algo);
      const { mldsaSeed, mldsaSecretKey, mldsaPublicKey } = await mldsa.generate(algo);
      return { eccSecretKey, eccPublicKey, mldsaSeed, mldsaSecretKey, mldsaPublicKey };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function sign(signatureAlgo, hashAlgo, eccSecretKey, eccPublicKey, mldsaSecretKey, dataDigest) {
  if (!isCompatibleHashAlgo(signatureAlgo, hashAlgo)) {
    // The signature hash algo MUST have digest larger than 256 bits
    // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#section-9.4
    throw new Error('Unexpected hash algorithm for PQC signature: digest size too short');
  }
  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { eccSignature } = await eccdsa.sign(signatureAlgo, hashAlgo, eccSecretKey, eccPublicKey, dataDigest);
      const { mldsaSignature } = await mldsa.sign(signatureAlgo, mldsaSecretKey, dataDigest);

      return { eccSignature, mldsaSignature };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function verify(signatureAlgo, hashAlgo, eccPublicKey, mldsaPublicKey, dataDigest, { eccSignature, mldsaSignature }) {
  if (!isCompatibleHashAlgo(signatureAlgo, hashAlgo)) {
    // The signature hash algo MUST have digest larger than 256 bits
    // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#section-9.4
    throw new Error('Unexpected hash algorithm for PQC signature: digest size too short');
  }
  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const eccVerifiedPromise = eccdsa.verify(signatureAlgo, hashAlgo, eccPublicKey, dataDigest, eccSignature);
      const mldsaVerifiedPromise = mldsa.verify(signatureAlgo, mldsaPublicKey, dataDigest, mldsaSignature);
      const verified = await eccVerifiedPromise && await mldsaVerifiedPromise;
      return verified;
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export function isCompatibleHashAlgo(signatureAlgo, hashAlgo) {
  // The signature hash algo MUST have digest larger than 256 bits
  // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#section-9.4
  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519:
      return getHashByteLength(hashAlgo) >= 32;
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function validateParams(algo, eccPublicKey, eccSecretKey, mldsaPublicKey, mldsaSeed) {
  const eccValidationPromise = eccdsa.validateParams(algo, eccPublicKey, eccSecretKey);
  const mldsaValidationPromise = mldsa.validateParams(algo, mldsaPublicKey, mldsaSeed);
  const valid = await eccValidationPromise && await mldsaValidationPromise;
  return valid;
}
