package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
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
  private BaseCollection encodedBasesCollection;
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
  private GroupElement hatQ;
  private GroupElement hatA;
  private BigInteger hatc;
  private List<String> challengeList;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private ProofStore<Object> proofStore;
  private GroupElement Ae;
  private GroupElement baseSmulti;
  private GroupElement ZPrime;
  private GroupElement hatZ;
  private BigInteger vPrime;
  private BigInteger vPrimePrime;
  private BaseIterator encodedVertexIterator;
  private BaseIterator encodedEdgeIterator;
  private GroupElement basesProduct;

  private void checkE(BigInteger e) {
    if (!e.isProbablePrime(keyGenParameters.getL_pt())) {
      throw new IllegalArgumentException("e is not prime");
    }

    if ((e.compareTo(keyGenParameters.getLowerBoundE()) < 0)
        || (e.compareTo(keyGenParameters.getUpperBoundE()) > 0)) {
      throw new IllegalArgumentException("e is not within range");
    }
  }

  public void computeQ() {
    gslog.info("compute Q");
    basesProduct = (QRElement) extendedPublicKey.getPublicKey().getQRGroup().getOne();

    BaseIterator baseIterator = encodedBasesCollection.createIterator(BASE.ALL);
    for (BaseRepresentation baseRepresentation : baseIterator) {
      basesProduct =
          basesProduct.multiply(
              baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
    }

    R_0 = extendedPublicKey.getPublicKey().getBaseR_0();

    vPrime = (BigInteger) proofStore.retrieve("issuing.recipient.vPrime");
    vPrimePrime = (BigInteger) proofStore.retrieve("recipient.vPrimePrime");
    m_0 = (BigInteger) proofStore.retrieve("bases.exponent.m_0");

    v = vPrimePrime.add(vPrime);

    GroupElement R_0multi = R_0.modPow(m_0);
    basesProduct = basesProduct.multiply(R_0multi);

    GroupElement Sv = baseS.modPow(v);
    GroupElement result = Sv.multiply(basesProduct);
    Q = baseZ.multiply(result.modInverse());
  }

  public void computehatQ() throws VerificationException {
    hatQ = A.modPow(e);

    if (hatQ.compareTo(Q) != 0) {
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
      final BaseCollection encodedBasesCollection,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {
    this.e = e;
    this.v = v;
    this.P_2 = P_2;
    this.A = A;
    this.extendedPublicKey = extendedPublicKey;
    this.n_2 = n_2;
    this.encodedBasesCollection = encodedBasesCollection;
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
    this.encodedVertexIterator = encodedBasesCollection.createIterator(BASE.VERTEX);
    this.encodedEdgeIterator = encodedBasesCollection.createIterator(BASE.EDGE);

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
    hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  public Boolean verifyChallenge() {
    return hatc.equals(cPrime);
  }

  public List<String> populateChallengeList() {
    challengeList = new ArrayList<String>();
    /** TODO add context in challenge list */
    GSContext gsContext =
        new GSContext(extendedPublicKey, keyGenParameters, graphEncodingParameters);
    List<String> contextList = gsContext.computeChallengeContext();
    challengeList.addAll(contextList);
    challengeList.add(String.valueOf(Q));
    challengeList.add(String.valueOf(A));
    challengeList.add(String.valueOf(hatA));
    challengeList.add(String.valueOf(n_2));

    return challengeList;
  }
}
