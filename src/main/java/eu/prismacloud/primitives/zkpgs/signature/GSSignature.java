package eu.prismacloud.primitives.zkpgs.signature;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
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
  private GSCommitment U;
  private KeyGenParameters keyGenParameters;
  private GroupElement A;
  private BigInteger e;
  private BigInteger v;
  private GroupElement Q;
  private BigInteger vbar;
  private BigInteger vPrimePrime;
  private GroupElement baseS;
  private GroupElement baseZ;
  private BigInteger modN;
  private Map<URN, BaseRepresentation> encodedEdges;
  private Map<URN, BaseRepresentation> encodedBases;
  private GroupElement R_i;
  private GroupElement R_i_j;
  private BigInteger d;
  private BigInteger eInverse;

  public GSSignature(
      final ExtendedPublicKey extendedPublicKey,
      GSCommitment U,
      Map<URN, BaseRepresentation> encodedBases,
      KeyGenParameters keyGenParameters) {
    this.U = U;
    this.encodedBases = encodedBases;
    this.keyGenParameters = keyGenParameters;
  }

  public GSSignature(GroupElement A, BigInteger e, BigInteger v) {
    this.A = A;
    this.e = e;
    this.v = v;
  }

  public GroupElement getA() {
    return A;
  }

  public BigInteger getE() {
    return e;
  }

  public BigInteger getV() {
    return v;
  }

  // TODO Lift computations to GSSigner; GSSignature should not have knowledge of the sk.

  public GSSignature blind() {
    int r_ALength = keyGenParameters.getL_n() + keyGenParameters.getL_statzk();
    BigInteger r_A = CryptoUtilsFacade.computeRandomNumber(r_ALength);
    GroupElement APrime = A.multiply(baseS.modPow(r_A));
    BigInteger vPrime = v.subtract(e.multiply(r_A));
    BigInteger ePrime =
        e.subtract(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1));
    return new GSSignature(APrime, ePrime, vPrime);
  }
}
