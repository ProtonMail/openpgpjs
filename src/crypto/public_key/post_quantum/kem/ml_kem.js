import enums from '../../../../enums';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mlkem_x25519: {
      const { Kyber768 } = await import('crystals-kyber-js');
      const kyberInstance = new Kyber768();
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
      const { Kyber768 } = await import('crystals-kyber-js');
      const kyberInstance = new Kyber768();
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
      const { Kyber768 } = await import('crystals-kyber-js');
      const kyberInstance = new Kyber768();
      const mlkemKeyShare = await kyberInstance.decap(mlkemCipherText, mlkemSecretKey);

      return mlkemKeyShare;
    }
    default:
      throw new Error('Unsupported KEM algorithm');
  }
}
