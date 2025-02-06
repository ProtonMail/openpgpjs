import * as mlkem from './ml_kem';
import * as mldsa from './ml_dsa';
import * as slhdsa from './slh_dsa';
import enums from '../../../enums';

export {
  mlkem,
  mldsa,
  slhdsa
};

const pqcAlgos = new Set([
  enums.publicKey.pqc_mldsa_ed25519,
  enums.publicKey.pqc_mlkem_x25519,
  enums.publicKey.pqc_slhdsa_shake128s
]);

export function isPostQuantumAlgo(algo) {
  return pqcAlgos.has(algo);
}

export function getRequiredHashAlgo(signatureAlgo) {
  switch (signatureAlgo) {
    case enums.publicKey.pqc_mldsa_ed25519:
      return mldsa.getRequiredHashAlgo(signatureAlgo);
    case enums.publicKey.pqc_slhdsa_shake128s:
      return slhdsa.getRequiredHashAlgo(signatureAlgo);
    default:
      throw new Error('Unsupported signature algorithm');
  }
}
