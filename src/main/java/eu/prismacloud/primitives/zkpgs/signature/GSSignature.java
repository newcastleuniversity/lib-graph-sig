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
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.Map;
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
      final ExtendedPublicKey extendedPublicKey,
      ICommitment U,
      Map<URN, BaseRepresentation> encodedBases,
      KeyGenParameters keyGenParameters) {

    this.extendedKeyPair = extendedKeyPair;
    this.U = U;
    this.encodedBases = encodedBases;
    this.keyGenParameters = keyGenParameters;
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
    this.modN = extendedPublicKey.getPublicKey().getModN();
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

  // TODO Lift computations to GSSigner; GSSignature should not have knowledge of the sk.


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
