import enums from '../../../../enums';

export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { DilithiumKeyPair, DilithiumLevel } = await import('@asanrom/dilithium');

      const level = DilithiumLevel.get(3);
      const keyPair = DilithiumKeyPair.generate(level);

      const mldsaSecretKey = keyPair.getPrivateKey().getBytes();
      const mldsaPublicKey = keyPair.getPublicKey().getBytes();

      return { mldsaSecretKey, mldsaPublicKey };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function sign(algo, mldsaSecretKey, dataDigest) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { DilithiumPrivateKey, DilithiumLevel } = await import('@asanrom/dilithium');
      const level = DilithiumLevel.get(3);
      const secretKey = DilithiumPrivateKey.fromBytes(mldsaSecretKey, level);
      const mldsaSignature = secretKey.sign(dataDigest).getBytes();
      return { mldsaSignature };
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}

export async function verify(algo, mldsaPublicKey, dataDigest, mldsaSignature) {
  switch (algo) {
    case enums.publicKey.pqc_mldsa_ed25519: {
      const { DilithiumPublicKey, DilithiumSignature, DilithiumLevel } = await import('@asanrom/dilithium');
      const level = DilithiumLevel.get(3);
      const publicKey = DilithiumPublicKey.fromBytes(mldsaPublicKey, level);
      const signature = DilithiumSignature.fromBytes(mldsaSignature, level);
      return publicKey.verifySignature(dataDigest, signature);
    }
    default:
      throw new Error('Unsupported signature algorithm');
  }
}
