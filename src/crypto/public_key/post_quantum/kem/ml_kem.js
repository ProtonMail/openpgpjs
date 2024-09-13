import enums from '../../../../enums';
import util from '../../../../util';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { ml_kem768 } = await import('@noble/post-quantum/ml-kem');
      const { publicKey: encapsulationKey, secretKey: decapsulationKey } = ml_kem768.keygen();

      return { mlkemPublicKey: encapsulationKey, mlkemSecretKey: decapsulationKey };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function encaps(algo, mlkemRecipientPublicKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { ml_kem768 } = await import('@noble/post-quantum/ml-kem');
      const { cipherText: mlkemCipherText, sharedSecret: mlkemKeyShare } = ml_kem768.encapsulate(mlkemRecipientPublicKey);

      return { mlkemCipherText, mlkemKeyShare };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function decaps(algo, mlkemCipherText, mlkemSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { ml_kem768 } = await import('@noble/post-quantum/ml-kem');
      const mlkemKeyShare = ml_kem768.decapsulate(mlkemCipherText, mlkemSecretKey);

      return mlkemKeyShare;
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function validateParams(algo, mlkemPublicKey, mlkemSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      // TODO confirm this is the best option performance- & security-wise (is key re-generation faster?)
      const { mlkemCipherText: validationCipherText, mlkemKeyShare: validationKeyShare } = await encaps(algo, mlkemPublicKey);
      const resultingKeyShare = await decaps(algo, validationCipherText, mlkemSecretKey);
      return util.equalsUint8Array(resultingKeyShare, validationKeyShare);
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}
