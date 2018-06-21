package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.signature.KeyGenSignature;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/** Generates key pair for the Signer */
public class GSSignerKeyPair implements IGSKeyPair {

  private static SignerPrivateKey privateKey;
  private static SignerPublicKey publicKey;
  private static KeyGenSignature keyGenSignature;
  private static SpecialRSAMod specialRSAMod = null;
  private static GroupElement S;
  private static BigInteger x_Z;
  private static BigInteger x_R;
  private static BigInteger x_R0;
  private static BigInteger R;
  private static BigInteger R_0;
  private static BigInteger Z;
  private static Group cg;
  private static final Logger log = GSLoggerConfiguration.getGSlog();
  private static Group qrGroup;

  /**
   * Instantiates a new Gs signer key pair.
   *
   * @param privateKey the private key
   * @param publicKey the public key
   */
  public GSSignerKeyPair(final SignerPrivateKey privateKey, final SignerPublicKey publicKey) {
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
  public static GSSignerKeyPair KeyGen() {

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

    return new GSSignerKeyPair(privateKey, publicKey);
  }

  /** TODO refactor generateKeySignature method */
  /** Generate key signature. */
  public void generateKeySignature() {
    byte[] digest = new byte[0];
    String hex;
    MessageDigest md;
    BigInteger r_a0;
    BigInteger r_aZ;
    BigInteger T_R0;
    BigInteger T_Z;
    BigInteger s_a0;
    BigInteger s_aZ;
    BigInteger c;

    BigInteger upperBound =
        specialRSAMod.getpPrime().multiply(specialRSAMod.getqPrime()).subtract(BigInteger.ONE);
    r_a0 = CryptoUtilsFacade.computeRandomNumber(BigInteger.ZERO, upperBound);
    r_aZ = CryptoUtilsFacade.computeRandomNumber(BigInteger.ZERO, upperBound);
    T_R0 = S.modPow(r_a0, specialRSAMod.getN());
    T_Z = S.modPow(r_aZ, specialRSAMod.getN());

    try {
      md = MessageDigest.getInstance("SHA-256");
      String contents;
      contents =
          specialRSAMod.getN().toString()
              + R_0.toString()
              + Z.toString()
              + S.toString()
              + T_R0.toString()
              + T_Z.toString();
      md.update(contents.getBytes(StandardCharsets.UTF_8));
      digest = md.digest();

      hex = String.format("%064x", new BigInteger(1, digest));
      System.out.println(hex);

      c = new BigInteger(1, digest);

      s_a0 = r_a0.add(c.multiply(x_R0));
      s_aZ = r_aZ.add(c.multiply(x_Z));

    } catch (NoSuchAlgorithmException e) {
      System.err.println("Algorithm for hash is not correct " + e.getMessage());
    }
  }

  /**
   * Verify key signature boolean.
   *
   * @param c the c
   * @param s_a0 the s a 0
   * @param s_aZ the s a z
   * @return the boolean
   */
  public Boolean verifyKeySignature(
      final BigInteger c, final BigInteger s_a0, final BigInteger s_aZ) {
    byte[] digest = new byte[0];

    String contents;
    String hex;
    MessageDigest md = null;
    BigInteger T_R0_hat, T_Z_hat, c_verification;

    T_R0_hat = R_0.modPow(c, specialRSAMod.getN()).multiply(S.modPow(s_a0, specialRSAMod.getN()));
    T_Z_hat = Z.modPow(c, specialRSAMod.getN()).multiply(S.modPow(s_aZ, specialRSAMod.getN()));
    contents =
        specialRSAMod.getN().toString()
            + R_0.toString()
            + Z.toString()
            + S.toString()
            + T_R0_hat.toString()
            + T_Z_hat.toString();
    md.update(contents.getBytes(StandardCharsets.UTF_8));
    Assert.notNull(md, "Message digest must not be null");
    digest = md.digest();

    hex = String.format("%064x", new BigInteger(1, digest));
    System.out.println(hex);

    c_verification = new BigInteger(1, digest);
    return c.equals(c_verification);
  }

  @Override
  public SignerPrivateKey getPrivateKey() {
    return privateKey;
  }

  @Override
  public SignerPublicKey getPublicKey() {
    return publicKey;
  }

  @Override
  public KeyGenSignature getSignature() {
    // TODO implement getSignature
    throw new RuntimeException("getSignature not implemented");
  }

  public Group getQRGroup() {
    return qrGroup;
  }
}
