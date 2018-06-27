package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.signature.KeyGenSignature;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.util.logging.Logger;

/** Generates key pair for the Signer */
public class SignerKeyPair {

  private static SignerPrivateKey privateKey;
  private static SignerPublicKey publicKey;
  private static KeyGenSignature keyGenSignature;
  private static SpecialRSAMod specialRSAMod = null;
  private static GroupElement S;
  private static BigInteger x_Z;
  private static BigInteger x_R;
  private static BigInteger x_R0;
  private static GroupElement R;
  private static GroupElement R_0;
  private static GroupElement Z;
  private static Group cg;
  private static final Logger log = GSLoggerConfiguration.getGSlog();
  private static Group qrGroup;

  /**
   * Instantiates a new Gs signer key pair.
   *
   * @param privateKey the private key
   * @param publicKey the public key
   */
  public SignerKeyPair(final SignerPrivateKey privateKey, final SignerPublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * Gets key gen signature.
   *
   * @return the key gen signature
   */
  public static KeyGenSignature getKeyGenSignature() {
    return keyGenSignature;
  }

  /**
   * Generate a key pair for the signer.
   *
   * @return GSSignerKeyPair gs signer key pair
   */
  public static SignerKeyPair KeyGen() {

    specialRSAMod = CryptoUtilsFacade.computeSpecialRSAModulus();

    qrGroup = new QRGroupPQ(specialRSAMod.getpPrime(), specialRSAMod.getqPrime());
    S = qrGroup.createGenerator();

    // ** TODO check if the computations with the group elements are correct
    x_Z = qrGroup.createElement().getValue();

    Z = S.modPow(x_Z, specialRSAMod.getN());

    x_R = qrGroup.createElement().getValue();
    R = S.modPow(x_R, specialRSAMod.getN());

    x_R0 = qrGroup.createElement().getValue();
    R_0 = S.modPow(x_R0, specialRSAMod.getN());

    cg = CryptoUtilsFacade.commitmentGroupSetup();
    privateKey =
        new SignerPrivateKey(
            specialRSAMod.getP(),
            specialRSAMod.getpPrime(),
            specialRSAMod.getQ(),
            specialRSAMod.getqPrime(),
            x_R,
            x_R0,
            x_Z);
    publicKey = new SignerPublicKey(specialRSAMod.getN(), R, R_0, S, Z);

    return new SignerKeyPair(privateKey, publicKey);
  }

  public SignerPrivateKey getPrivateKey() {
    return privateKey;
  }

  public SignerPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Gets qr group.
   *
   * @return the qr group
   */
  public Group getQRGroup() {
    return qrGroup;
  }
}
