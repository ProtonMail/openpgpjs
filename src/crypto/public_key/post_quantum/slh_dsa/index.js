import enums from '../../../../enums';
import { getRandomBytes } from '../../../random';


export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_slhdsa_shake128s: {
      const { slh_dsa_shake_128s } = await import('@noble/post-quantum/slh-dsa');
      const { secretKey: slhdsaSecretKey, publicKey: slhdsaPublicKey } = slh_dsa_shake_128s.keygen();

      return { slhdsaSecretKey, slhdsaPublicKey };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function sign(signatureAlgo, hashAlgo, slhdsaSecretKey, dataDigest) {
  if (hashAlgo !== getRequiredHashAlgo(signatureAlgo)) {
    // The signature hash algo MUST be set to the specified algorithm, see
    // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-06.html#section-6.1.1
    throw new Error('Unexpected hash algorithm for PQC signature');
  }

  switch (signatureAlgo) {
    case enums.publicKey.pqc_slhdsa_shake128s: {
      const { slh_dsa_shake_128s } = await import('@noble/post-quantum/slh-dsa');
      const slhdsaSignature = slh_dsa_shake_128s.sign(slhdsaSecretKey, dataDigest);
      return { slhdsaSignature };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function verify(signatureAlgo, hashAlgo, slhdsaPublicKey, dataDigest, { slhdsaSignature }) {
  if (hashAlgo !== getRequiredHashAlgo(signatureAlgo)) {
    // The signature hash algo MUST be set to the specified algorithm, see
    // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-06.html#section-6.1.1
    throw new Error('Unexpected hash algorithm for PQC signature');
  }

  switch (signatureAlgo) {
    case enums.publicKey.pqc_slhdsa_shake128s: {
      const { slh_dsa_shake_128s } = await import('@noble/post-quantum/slh-dsa');
      return slh_dsa_shake_128s.verify(slhdsaPublicKey, dataDigest, slhdsaSignature);
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function validateParams(algo, slhdsaPublicKey, slhdsaSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_slhdsa_shake128s: {
      // TODO check if more performant validation is possible via public key re-derivation
      const randomBytes = getRandomBytes(16);
      const { slhdsaSignature } = await sign(algo, slhdsaSecretKey, randomBytes);
      const trialSignatureVerified = await verify(algo, slhdsaPublicKey, randomBytes, slhdsaSignature);
      return trialSignatureVerified;
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export function getRequiredHashAlgo(signatureAlgo) {
  // See https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-06.html#section-6.1.1
  switch (signatureAlgo) {
    case enums.publicKey.pqc_slhdsa_shake128s:
      return enums.hash.sha3_256;
    default:
      throw new Error('Unsupported signature algorithm');
  }
}
