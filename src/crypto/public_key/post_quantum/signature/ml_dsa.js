import enums from '../../../../enums';
import hash from '../../../hash';
import { getRandomBytes } from '../../../random';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa');
      const { secretKey: mldsaSecretKey, publicKey: mldsaPublicKey } = ml_dsa65.keygen();
      return { mldsaSecretKey, mldsaPublicKey };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function sign(algo, mldsaSecretKey, dataDigest) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa');
      const mldsaSignature = ml_dsa65.sign(mldsaSecretKey, dataDigest);
      return { mldsaSignature };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function verify(algo, mldsaPublicKey, dataDigest, mldsaSignature) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa');
      return ml_dsa65.verify(mldsaPublicKey, dataDigest, mldsaSignature);
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function validateParams(algo, mldsaPublicKey, mldsaSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const message = getRandomBytes(8);
      const hashAlgo = enums.hash.sha256;
      const hashed = await hash.digest(hashAlgo, message);
      const { mldsaSignature } = await sign(algo, mldsaSecretKey, hashed);
      return verify(algo, mldsaPublicKey, hashed, mldsaSignature);
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}
