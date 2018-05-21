package eu.prismacloud.primitives.grs.keys;

import eu.prismacloud.primitives.grs.signature.KeyGenSignature;
import eu.prismacloud.primitives.grs.utils.crypto.CommitmentGroup;
import eu.prismacloud.primitives.grs.utils.CryptoUtilsFacade;
import eu.prismacloud.primitives.grs.utils.GSLoggerConfiguration;
import eu.prismacloud.primitives.grs.utils.crypto.Group;
import eu.prismacloud.primitives.grs.utils.crypto.GroupElement;
import eu.prismacloud.primitives.grs.utils.NumberConstants;
import eu.prismacloud.primitives.grs.utils.crypto.QRGroupPQ;
import eu.prismacloud.primitives.grs.utils.crypto.SpecialRSAMod;
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
  private static BigInteger x_R_0;
  private static BigInteger R_0;
  private static BigInteger Z;
  private static CommitmentGroup cg;
  private static final Logger log = GSLoggerConfiguration.getGSlog();

  /**
   * Instantiates a new Gs signer key pair.
   *
   * @param privateKey the private key
   * @param publicKey the public key
   */
  public GSSignerKeyPair(final SignerPrivateKey privateKey, final SignerPublicKey publicKey) {
    GSSignerKeyPair.privateKey = privateKey;
    GSSignerKeyPair.publicKey = publicKey;
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

    Group qrGroup = new QRGroupPQ(specialRSAMod.getP_prime(), specialRSAMod.getQ_prime());
    S = qrGroup.createGenerator();

    BigInteger upperBound =
        specialRSAMod.getP_prime().multiply(specialRSAMod.getQ_prime()).subtract(BigInteger.ONE);
    x_Z = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);
    Z = S.modPow(x_Z, specialRSAMod.getN());
    x_R_0 = CryptoUtilsFacade.computeRandomNumber(NumberConstants.TWO.getValue(), upperBound);
    R_0 = S.modPow(x_R_0, specialRSAMod.getN());
    cg = CryptoUtilsFacade.commitmentGroupSetup();
    privateKey =
        new SignerPrivateKey(
            specialRSAMod.getP(),
            specialRSAMod.getP_prime(),
            specialRSAMod.getQ(),
            specialRSAMod.getQ_prime(),
            x_R_0,
            x_Z);
    publicKey = new SignerPublicKey(specialRSAMod.getN(), R_0, S, Z);

    return new GSSignerKeyPair(privateKey, publicKey);
  }

  /** Generate key signature. */
  public void generateKeySignature() {
    byte[] digest = new byte[0];
    String hex;
    MessageDigest md;
    BigInteger r_a0, r_aZ, T_R0, T_Z, s_a0, s_aZ, c = null;
    BigInteger upperBound =
        specialRSAMod.getP_prime().multiply(specialRSAMod.getQ_prime()).subtract(BigInteger.ONE);
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

      s_a0 = r_a0.add(c.multiply(x_R_0));
      s_aZ = r_aZ.add(c.multiply(x_Z));

    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }

  public Boolean verifyKeySignature(final BigInteger c, final BigInteger s_a0, BigInteger s_aZ) {
    byte[] digest = new byte[0];

    String contents, hex;
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
    digest = md.digest();

    hex = String.format("%064x", new BigInteger(1, digest));
    System.out.println(hex);

    c_verification = new BigInteger(1, digest);
    return c.equals(c_verification);
  }

  public SignerPrivateKey getPrivateKey() {
    return privateKey;
  }

  public SignerPublicKey getPublicKey() {
    return publicKey;
  }

  public KeyGenSignature getSignature() {
    // TODO implement getSignature
    throw new RuntimeException("getSignature not implemented");
  }
}
