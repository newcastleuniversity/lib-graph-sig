package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class CorrectnessVerifier implements IVerifier {

  private BigInteger e;
  private BigInteger hatd;
  private BigInteger n_2;
  private Map<URN, BaseRepresentation> encodedBases;
  private BigInteger v;
  private ProofSignature P_2;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger cPrime;
  private GroupElement baseZ;
  private GroupElement A;
  private GroupElement baseS;
  private GroupElement R_0;
  private BigInteger m_0;
  private BigInteger modN;
  private Map<URN, BaseRepresentation> encodedVertices;
  private Map<URN, BaseRepresentation> encodedEdges;
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private GroupElement Q;
  private GroupElement R_i;
  private GroupElement R_i_j;
  private BigInteger hatQ;
  private GroupElement hatA;
  private BigInteger hatc;
  private List<String> challengeList;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private List<String> contextList;
  private ProofStore<Object> proofStore;
  private GroupElement Ae;
  private GroupElement baseSmulti;
  private GroupElement ZPrime;
  private GroupElement hatZ;
  private BigInteger vPrime;
  private BigInteger vPrimePrime;

  private void checkE(BigInteger e) {
    if (!e.isProbablePrime(80)) {
      throw new IllegalArgumentException("e is not prime");
    }
    int maxBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    BigInteger min = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);
    BigInteger max = min.add(NumberConstants.TWO.getValue().pow(maxBitLength));

    //    BigInteger min = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);
    //    BigInteger max =
    //        min.add(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_prime_e() - 1));

    if ((e.compareTo(min) < 0) || (e.compareTo(max) > 0)) {
      throw new IllegalArgumentException("e is not within range");
    }
  }

  public void computeQ() {
//    for (BaseRepresentation encodedBase : encodedBases.values()) {
//      if (encodedBase.getExponent() != null) {
//        if (encodedBase.getBaseType() == BASE.VERTEX) {
//          if (R_i == null) {
//            R_i = encodedBase.getBase().modPow(encodedBase.getExponent(), modN);
//          } else {
//            R_i = R_i.multiply(encodedBase.getBase().modPow(encodedBase.getExponent(), modN));
//          }
//
//        } else if (encodedBase.getBaseType() == BASE.EDGE) {
//
//          if (R_i_j == null) {
//
//            R_i_j = encodedBase.getBase().modPow(encodedBase.getExponent(), modN);
//
//          } else {
//            R_i_j = R_i_j.multiply(encodedBase.getBase().modPow(encodedBase.getExponent(), modN));
//          }
//        }
//      }
//    }

//    R_0 = (BaseRepresentation) proofStore.retrieve("bases.R_0");//encodedBases.get(URN.createZkpgsURN("bases.R_0"));
    R_0 = extendedPublicKey.getPublicKey().getBaseR_0();

    vPrime = (BigInteger) proofStore.retrieve("issuing.recipient.vPrime");
//    vPrimePrime = (BigInteger) P_2.get("proofsignature.vPrimePrime");
    vPrimePrime = (BigInteger) proofStore.retrieve("recipient.vPrimePrime");
    m_0 = (BigInteger) proofStore.retrieve("bases.exponent.m_0");

    gslog.info("signer vPrime: " + vPrime);
    gslog.info("signer vPrimePrime: " + vPrimePrime);

       v = vPrimePrime.add(vPrime);

       gslog.info("recipient.R_0: " + R_0);

       gslog.info("recipient.m_0: " + m_0);

       GroupElement R_0multi = R_0.modPow(m_0);
        Ae = A.modPow(e);
        baseSmulti = baseS.modPow(v);
       ZPrime = A.modPow(e).multiply(baseS.modPow(vPrimePrime));

       hatZ = ZPrime.multiply(R_0multi);

       gslog.info("correctness verifier hatZ: " + hatZ);
       gslog.info("correctness verifier baseZ: " + baseZ);
       

//    BigInteger invertible =
//        baseS.modPow(v, modN)
//            .multiply(R_0.getBase().modPow(R_0.getExponent(), modN).getValue())
//            .multiply(R_i.getValue())
//            .multiply(R_i_j.getValue())
//            .mod(modN);

//    BigInteger invertible =
//            baseS.modPow(v, modN)
//                .multiply(R_0.getBase().modPow(R_0.getExponent(), modN).getValue()).getValue();
//    Q = baseZ.multiply(invertible.modInverse(modN)).mod(modN);
    gslog.info("recipient Q: " + Q);
    gslog.info("recipient Z: " + baseZ);
    gslog.info("recipient S: " + baseS);
    
  }

  public void computehatQ() throws VerificationException {
//    hatQ = A.modPow(e, modN);
//
//    gslog.info("hatQ: " + hatQ);
//
//    gslog.info("recipient e: "  + e);


    if (hatZ.compareTo(baseZ) != 0) {
      throw new VerificationException("Q cannot be verified");
    }
  }

  public void preChallengePhase(
      final BigInteger e,
      final BigInteger v,
      final ProofSignature P_2,
      final GroupElement A,
      final ExtendedPublicKey extendedPublicKey,
      final BigInteger n_2,
      final Map<URN, BaseRepresentation> encodedBases,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters)
      throws VerificationException {
    this.e = e;
    this.v = v;
    this.P_2 = P_2;
    this.A = A;
    this.extendedPublicKey = extendedPublicKey;
    this.n_2 = n_2;
    this.encodedBases = encodedBases;
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();

    checkE(this.e);
    verifySignature();
    verifyP2();
  }

  private void verifyP2() {
    cPrime = (BigInteger) P_2.get("P_2.cPrime");
    hatd = (BigInteger) P_2.get("P_2.hatd");
    
    hatA = A.modPow(cPrime.add(hatd.multiply(e)));
  }

  public void verifySignature() {
    computeQ();
    try {
      computehatQ();
    } catch (VerificationException ve) {
      gslog.log(Level.SEVERE, ve.getMessage());
    }
  }

  public void computeChallenge() throws NoSuchAlgorithmException {

    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(populateChallengeList(), keyGenParameters.getL_H());
  }

  public Boolean verifyChallenge() {
    return hatc.equals(cPrime);
  }

  public List<String> populateChallengeList() {
    challengeList = new ArrayList<String>();
    /** TODO add context in challenge list */
    contextList =
        GSContext.computeChallengeContext(
            extendedPublicKey, keyGenParameters, graphEncodingParameters);
    challengeList.add(String.valueOf(Q));
    challengeList.add(String.valueOf(A));
    challengeList.add(String.valueOf(hatA));
    challengeList.add(String.valueOf(n_2));

    return challengeList;
  }
}
