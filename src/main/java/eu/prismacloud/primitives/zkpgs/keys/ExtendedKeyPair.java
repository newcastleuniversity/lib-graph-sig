package eu.prismacloud.primitives.zkpgs.keys;

/** Class representing the extended key pair */
public final class ExtendedKeyPair {

  private final ExtendedPublicKey extendedPublicKey;
  private final ExtendedPrivateKey extendedPrivateKey;

  public ExtendedKeyPair(
      final ExtendedPublicKey extendedPublicKey, final ExtendedPrivateKey extendedPrivateKey) {
    this.extendedPublicKey = extendedPublicKey;
    this.extendedPrivateKey = extendedPrivateKey;
  }

  public ExtendedPublicKey getExtendedPublicKey() {
    return this.extendedPublicKey;
  }

  public ExtendedPrivateKey getExtendedPrivateKey() {
    return this.extendedPrivateKey;
  }

  public SignerPublicKey getPublicKey() {
    return this.extendedPublicKey.getPublicKey();
  }

  public SignerPrivateKey getPrivateKey() {
    return this.extendedPrivateKey.getPrivateKey();
  }
}
