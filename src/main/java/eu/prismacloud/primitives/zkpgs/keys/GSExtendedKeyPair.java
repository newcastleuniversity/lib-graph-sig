package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.signature.EncodingSignature;

public class GSExtendedKeyPair implements IGSExtendedKeyPair {
  private ExtendedPublicKey extendedPublicKey;
  private ExtendedPrivateKey extendedPrivateKey;

  public EncodingSignature getEncodingSignature() {
    return encodingSignature;
  }

  private EncodingSignature encodingSignature;

  public ExtendedPublicKey getPublicKey() {
    return null;
  }

  public ExtendedPrivateKey getPrivateKey() {
    return null;
  }
}
