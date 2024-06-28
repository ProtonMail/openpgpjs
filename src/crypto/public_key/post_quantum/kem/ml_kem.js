import enums from '../../../../enums';
import util from '../../../../util';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { MlKem768 } = await import('@openpgp/crystals-kyber-js');
      const kyberInstance = new MlKem768();
      const [encapsulationKey, decapsulationKey] = await kyberInstance.generateKeyPair();

      return { mlkemPublicKey: encapsulationKey, mlkemSecretKey: decapsulationKey };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function encaps(algo, mlkemRecipientPublicKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { MlKem768 } = await import('@openpgp/crystals-kyber-js');
      const kyberInstance = new MlKem768();
      const [mlkemCipherText, mlkemKeyShare] = await kyberInstance.encap(mlkemRecipientPublicKey);

      return { mlkemCipherText, mlkemKeyShare };
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}

export async function decaps(algo, mlkemCipherText, mlkemSecretKey) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { MlKem768 } = await import('@openpgp/crystals-kyber-js');
      const kyberInstance = new MlKem768();
      const mlkemKeyShare = await kyberInstance.decap(mlkemCipherText, mlkemSecretKey);

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
