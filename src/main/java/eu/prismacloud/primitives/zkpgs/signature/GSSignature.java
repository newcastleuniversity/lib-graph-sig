package eu.prismacloud.primitives.zkpgs.signature;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.EEAlgorithm;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GSSignature {
  private static Logger gslog = GSLoggerConfiguration.getGSlog();
  private ExtendedKeyPair extendedKeyPair;
  private ICommitment U;
  private KeyGenParameters keyGenParameters;
  private BigInteger A;
  private BigInteger e;
  private BigInteger v;
  private BigInteger Q;
  private BigInteger vbar;
  private BigInteger vPrimePrime;
  private GroupElement baseS;
  private GroupElement baseZ;
  private BigInteger modN;
  private Map<URN, BaseRepresentation> encodedEdges;
  private Map<URN, BaseRepresentation> encodedBases;
  private BigInteger R_i;
  private BigInteger R_i_j;
  private BigInteger d;
  private BigInteger eInverse;

  public GSSignature(
      final ExtendedKeyPair extendedKeyPair,
      ICommitment U,
      Map<URN, BaseRepresentation> encodedBases,
      KeyGenParameters keyGenParameters) {

    this.extendedKeyPair = extendedKeyPair;
    this.U = U;
    this.encodedBases = encodedBases;
    this.keyGenParameters = keyGenParameters;
    this.baseS = extendedKeyPair.getPublicKey().getBaseS();
    this.baseZ = extendedKeyPair.getPublicKey().getBaseZ();
    this.modN = extendedKeyPair.getPublicKey().getModN();
  }

  public GSSignature(BigInteger A, BigInteger e, BigInteger v) {
    this.A = A;
    this.e = e;
    this.v = v;
  }

  public BigInteger getA() {
    return this.A;
  }

  public BigInteger getE() {
    return this.e;
  }

  public BigInteger getV() {
    return this.v;
  }

  public BigInteger computeQ() {
    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);
    vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
    vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);

    for (BaseRepresentation encodedBase : encodedBases.values()) {
      if (encodedBase.getBaseType() == BASE.VERTEX) {
        R_i =
            R_i.multiply(encodedBase.getBase().modPow(encodedBase.getExponent(), modN).getValue());
      } else if (encodedBase.getBaseType() == BASE.EDGE) {
        R_i_j =
            R_i_j.multiply(
                encodedBase.getBase().modPow(encodedBase.getExponent(), modN).getValue());
      }
    }

    BigInteger invertible = baseS.modPow(vPrimePrime, modN).multiply(R_i).multiply(R_i_j).mod(modN);
    Q = baseZ.multiply(invertible.modInverse(modN)).mod(modN);

    return Q;
  }

  public BigInteger computeA() {
    BigInteger order =
        extendedKeyPair
            .getPrivateKey()
            .getpPrime()
            .multiply(extendedKeyPair.getPrivateKey().getqPrime());

    EEAlgorithm.computeEEAlgorithm(e, order);
    d = EEAlgorithm.getS();
    /** TODO check if the EEAlgorithm calculates the modInverse correctly */
    gslog.log(Level.INFO, "d eea: " + d);
    gslog.log(Level.INFO, "d modInverse: " + e.modInverse(order));
    A = Q.modPow(d, modN);
    return A;
  }

  public GSSignature blind(BigInteger A, BigInteger e, BigInteger v) {

    int r_ALength = keyGenParameters.getL_n() + keyGenParameters.getL_statzk();
    BigInteger r_A = CryptoUtilsFacade.computeRandomNumber(r_ALength);
    BigInteger APrime = A.mod(modN).multiply(baseS.modPow(r_A, modN).getValue());
    BigInteger vPrime = v.subtract(e.multiply(r_A));
    BigInteger ePrime =
        e.subtract(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1));

    return new GSSignature(A, e, v);
  }
}
