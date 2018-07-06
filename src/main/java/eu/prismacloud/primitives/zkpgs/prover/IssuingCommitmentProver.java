package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** The type Commitment prover for issuing. */
public class IssuingCommitmentProver implements IProver, Storable {

  private final GroupElement baseS;
  private ICommitment commitment;
  private BigInteger vPrime;
  private GroupElement R_0;
  private BigInteger nonce;
  private KeyGenParameters keyGenParameters;
  private final GraphEncodingParameters graphEncodingParameters;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger tildevPrime;
  private BigInteger tildem_0;
  private BigInteger tildem_i;
  private BigInteger tildem_i_j;
  private Map<URN, BaseRepresentation> edgesPrime;
  private Map<URN, BaseRepresentation> verticesPrime;
  private List<String> challengeList = new ArrayList<String>();
  private Map<URN, BaseRepresentation> encodedBases;
  private Map<String, BigInteger> edgeBases;
  private GroupElement tildeU;
  private BigInteger cChallenge;
  private BigInteger m_0;
  private Map<String, BigInteger> vertexResponses;
  private Map<String, BigInteger> edgeResponses;
  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private BigInteger hatm_i;
  private BigInteger hatm_i_j;
  private List<String> contextList;

  /**
   * Instantiates a new Commitment prover.
   *
   * @param commitment the commitment
   * @param vPrime the v prime
   * @param R_0 the r 0
   * @param m_0 the m 0
   * @param nonce the nonce
   * @param keyGenParameters the key gen parameters
   * @param extendedPublicKey the extended public key
   */
  public IssuingCommitmentProver(
      ICommitment commitment,
      BigInteger vPrime,
      GroupElement R_0,
      BigInteger m_0,
      BigInteger nonce,
      KeyGenParameters keyGenParameters,
      GraphEncodingParameters graphEncodingParameters,
      ExtendedPublicKey extendedPublicKey) {

    this.commitment = commitment;
    this.vPrime = vPrime;
    this.R_0 = R_0;
    this.m_0 = m_0;
    this.nonce = nonce;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.extendedPublicKey = extendedPublicKey;
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
  }

  @Override
  public void createWitnessRandomness() {

    int tildevPrimeBitLength =
        keyGenParameters.getL_n() + 2 * keyGenParameters.getL_statzk() + keyGenParameters.getL_H();

    tildevPrime = CryptoUtilsFacade.computeRandomNumber(tildevPrimeBitLength);

    int mBitLength =
        keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

    tildem_0 = CryptoUtilsFacade.computeRandomNumber(mBitLength);

    verticesPrime = commitment.getVertices();
    edgesPrime = commitment.getEdges();
    Map<URN, BigInteger> vertexWitnessRandomness = new HashMap<>();
    URN urnVertex;
    URN urnEdge;

    int i = 0;
    for (Map.Entry<URN, BaseRepresentation> entry : verticesPrime.entrySet()) {
      urnVertex =
          URN.createURN(
              URN.getZkpgsNameSpaceIdentifier(),
              "issuing.commitmentprover.witnesses.vertex.tildem_" + i);
      tildem_i = CryptoUtilsFacade.computeRandomNumber(mBitLength);
      vertexWitnessRandomness.put(urnVertex, tildem_i);
      i++;
    }

    int j = 0;
    for (Map.Entry<URN, BaseRepresentation> entry : edgesPrime.entrySet()) {
      urnEdge =
          URN.createURN(
              URN.getZkpgsNameSpaceIdentifier(),
              "issuing.commitmentprover.witnesses.edge.tildem_i_j" + j);
      tildem_i_j = CryptoUtilsFacade.computeRandomNumber(mBitLength);
      vertexWitnessRandomness.put(urnEdge, tildem_i_j);
      j++;
    }
  }

  @Override
  public void computeWitness() {
    GroupElement baseSvTildePrime;
    BigInteger R_0tildem_0;
    R_0tildem_0 = R_0.modPow(tildem_0).getValue();

    List<GroupElement> bases = new ArrayList<>();
    List<BigInteger> exponents = new ArrayList<>();
    bases.add(R_0);
    exponents.add(tildem_0);

    for (Map.Entry<URN, BaseRepresentation> base : verticesPrime.entrySet()) {
      bases.add(base.getValue().getBase());
      exponents.add(base.getValue().getExponent());
    }
    for (Map.Entry<URN, BaseRepresentation> edgeBase : edgesPrime.entrySet()) {
      bases.add(edgeBase.getValue().getBase());
      exponents.add(edgeBase.getValue().getExponent());
    }

    baseSvTildePrime = baseS.modPow(tildevPrime);

    tildeU = baseSvTildePrime.multiBaseExp(bases, exponents);
  }

  @Override
  public BigInteger computeChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
    return cChallenge;
  }

  private List<String> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    //    R = extendedPublicKey.getPublicKey().getBasesR();
    //    R_0 = extendedPublicKey.getPublicKey().getBaseR_0();
    contextList =
        GSContext.computeChallengeContext(
            extendedPublicKey, keyGenParameters, graphEncodingParameters);
    encodedBases = extendedPublicKey.getBases();

    challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getModN()));
    challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseS().getValue()));
    challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseZ().getValue()));
    //    challengeList.add(R);
    challengeList.add(String.valueOf(R_0.getValue()));

    /** TODO check bases */
    for (int i = 1; i <= encodedBases.size(); i++) {
      challengeList.add(
          String.valueOf(encodedBases.get(URN.createZkpgsURN("R_" + i)).getBase().getValue()));
    }
    /** TODO fix edge bases. use the bases map for edge bases */
    for (int j = 1; j <= edgeBases.size(); j++) {
      challengeList.add(String.valueOf(edgeBases.get("R_" + j)));
    }

    challengeList.add(String.valueOf(commitment.getCommitment()));
    challengeList.add(String.valueOf(tildeU));
    challengeList.add(String.valueOf(nonce));

    return challengeList;
  }

  @Override
  public void computeResponses() {
    BaseRepresentation baseRepresentation;

    hatvPrime = tildevPrime.add(cChallenge.multiply(vPrime));
    hatm_0 = tildem_0.add(cChallenge.multiply(m_0));

    for (int i = 0; i < commitment.getVertices().size(); i++) {
      baseRepresentation =
          commitment
              .getVertices()
              .get(
                  URN.createURN(
                      URN.getZkpgsNameSpaceIdentifier(),
                      "R_" + i)); // FIXME correct urn path for bases
      hatm_i = tildem_i.add(cChallenge.multiply(baseRepresentation.getExponent()));
      vertexResponses.put("hatm_" + i, hatm_i);
    }

    for (int j = 0; j < commitment.getEdges().size(); j++) {
      baseRepresentation =
          commitment
              .getEdges()
              .get(
                  URN.createURN(
                      URN.getZkpgsNameSpaceIdentifier(),
                      "hatm_i_j" + j)); // FIXME  correct urn path for edge bases
      hatm_i_j = tildem_i_j.add(cChallenge.multiply(baseRepresentation.getExponent()));
      edgeResponses.put("hatm_i_j" + j, hatm_i_j);
    }
  }

  /**
   * Create proof signature proof signature.
   *
   * @return the proof signature
   */
  public ProofSignature createProofSignature() {
    Map<URN, Object> proofSignatureElements = new HashMap<>();

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.c"), cChallenge);

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"), hatvPrime);
    // TODO check if hatm_0 is needed inside the proofsignature
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatm_0"), hatm_0);

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatm_i"), vertexResponses);

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatm_i_j"), edgeResponses);
    return new ProofSignature(proofSignatureElements);
  }

  @Override
  public void store(URN urn, ProofObject proofObject) {}

  @Override
  public ProofObject retrieve(URN urn) {
    return null;
  }
}
