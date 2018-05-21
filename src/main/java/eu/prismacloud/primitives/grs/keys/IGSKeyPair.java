package eu.prismacloud.primitives.grs.keys;

import eu.prismacloud.primitives.grs.signature.KeyGenSignature;

public interface IGSKeyPair {
  SignerPublicKey getPublicKey();

  SignerPrivateKey getPrivateKey();

  KeyGenSignature getSignature();
}
