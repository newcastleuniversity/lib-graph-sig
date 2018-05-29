package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.signature.KeyGenSignature;

public interface IGSKeyPair {
  SignerPublicKey getPublicKey();

  SignerPrivateKey getPrivateKey();

  KeyGenSignature getSignature();
}
