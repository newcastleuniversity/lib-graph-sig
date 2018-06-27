package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class CorrectnessVerifier implements IVerifier {

  private BigInteger e;
  private final BigInteger hatd;
  private BigInteger n_2;
  private Map<URN, BaseRepresentation> encodedBases;
  private BigInteger v;
  private ProofSignature P_2;
  private ExtendedPublicKey extendedPublicKey;
  private final BigInteger cPrime;
  private final BigInteger Z;
  private BigInteger A;
  private final BigInteger S;
  private final BigInteger R_0;
  private final BigInteger m_0;
  private final BigInteger modN;
  private final Map<URN, BaseRepresentation> encodedVertices;
  private final Map<URN, BaseRepresentation> encodedEdges;
  private KeyGenParameters keyGenParameters;
  private BigInteger Q;
  private BigInteger R_i;
  private BigInteger R_i_j;
  private BigInteger hatQ;
  private BigInteger hatA;
  private BigInteger hatc;
  private List<BigInteger> challengeList;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public CorrectnessVerifier(
      BigInteger e,
      BigInteger v,
      BigInteger cPrime,
      BigInteger hatd,
      BigInteger Z,
      BigInteger A,
      BigInteger S,
      BigInteger R_0,
      BigInteger m_0,
      BigInteger modN,
      Map<URN, BaseRepresentation> encodedVertices,
      Map<URN, BaseRepresentation> encodedEdges,
      BigInteger n_2,
      KeyGenParameters keyGenParameters) {

    checkE(e);
    this.e = e;
    this.v = v;
    this.cPrime = cPrime;
    this.hatd = hatd;
    this.Z = Z;
    this.A = A;
    this.S = S;
    this.R_0 = R_0;
    this.m_0 = m_0;
    this.modN = modN;
    this.encodedVertices = encodedVertices;
    this.encodedEdges = encodedEdges;
    this.n_2 = n_2;
    this.keyGenParameters = keyGenParameters;
  }

  private void checkE(BigInteger e) {
    if (!e.isProbablePrime(80)) {
      throw new IllegalArgumentException("e is not prime");
    }
    BigInteger min = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);
    BigInteger max =
        min.add(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_prime_e() - 1));

    if ((e.compareTo(min) < 0) || (e.compareTo(max) > 0)) {
      throw new IllegalArgumentException("e is not within range");
    }
  }

  public void computeQ() {
    for (BaseRepresentation encodedVertex : encodedVertices.values()) {
      R_i =
          R_i.multiply(
              encodedVertex.getBase().modPow(encodedVertex.getExponent(), modN).getValue());
    }

    for (BaseRepresentation encodedEdge : encodedEdges.values()) {
      R_i_j =
          R_i_j.multiply(encodedEdge.getBase().modPow(encodedEdge.getExponent(), modN).getValue());
    }

    BigInteger invertible =
        S.modPow(v, modN).multiply(R_0.modPow(m_0, modN)).multiply(R_i).multiply(R_i_j).mod(modN);
    Q = Z.multiply(invertible.modInverse(modN)).mod(modN);
  }

  public void computehatQ() throws VerificationException {
    hatQ = A.modPow(e, modN);

    if (!hatQ.equals(Q)) {
      throw new VerificationException("Q is not correct");
    }
  }

  public void preChallengePhase(
      final BigInteger e,
      final BigInteger v,
      final ProofSignature P_2,
      final BigInteger A,
      final ExtendedPublicKey extendedPublicKey,
      final BigInteger n_2,
      final Map<URN, BaseRepresentation> encodedBases,
      final KeyGenParameters keyGenParameters)
      throws VerificationException {
    this.e = e;
    this.v = v;
    this.P_2 = P_2;
    this.A = A;
    this.extendedPublicKey = extendedPublicKey;
    this.n_2 = n_2;
    this.encodedBases = encodedBases;
    this.keyGenParameters = keyGenParameters;

    checkE(this.e);
    verifySignature();
    verifyP2();
  }

  private void verifyP2() {
    hatA = A.modPow(cPrime.add(hatd.multiply(e)), modN);
  }

  public void verifySignature() {
    computeQ();
    try {
      computehatQ();
    } catch (VerificationException ve) {
      gslog.log(Level.SEVERE, ve.getMessage());
    }
  }

  public void computeChallenge() {

    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(populateChallengeList(), keyGenParameters.getL_H());
  }

  public Boolean verifyChallenge() {
    return hatc.equals(cPrime);
  }

  public List<BigInteger> populateChallengeList() {
    /** TODO add context in challenge list */
    challengeList.add(Q);
    challengeList.add(A);
    challengeList.add(hatA);
    challengeList.add(n_2);

    return challengeList;
  }
}
