package eu.prismacloud.primitives.zkpgs.keys;

/** Class representing the extended key pair */
public final class ExtendedKeyPair extends SignerKeyPair {

  private final ExtendedPublicKey extendedPublicKey;
  private final ExtendedPrivateKey extendedPrivateKey;

  public ExtendedKeyPair(
      final ExtendedPublicKey extendedPublicKey, final ExtendedPrivateKey extendedPrivateKey) {
    super(extendedPrivateKey.getPrivateKey(), extendedPublicKey.getPublicKey());

    this.extendedPublicKey = extendedPublicKey;
    this.extendedPrivateKey = extendedPrivateKey;
  }

  public ExtendedPublicKey getExtendedPublicKey() {
    return extendedPublicKey;
  }

  public ExtendedPrivateKey getExtendedPrivateKey() {
    return extendedPrivateKey;
  }

  public SignerPublicKey getPublicKey() {
    return extendedPublicKey.getPublicKey();
  }

  public SignerPrivateKey getPrivateKey() {
    return extendedPrivateKey.getPrivateKey();
  }
}
