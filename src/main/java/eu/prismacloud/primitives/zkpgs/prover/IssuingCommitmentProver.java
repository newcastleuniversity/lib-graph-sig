package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** The type Commitment prover for issuing. */
public class IssuingCommitmentProver implements IProver, Storable {

  private ICommitment commitment;
  private BigInteger vPrime;
  private Map<URN, BaseRepresentation> vertices;
  private GroupElement R_0;
  private BigInteger nonce;
  private KeyGenParameters keyGenParameters;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger tildevPrime;
  private BigInteger tildem_0;
  private BigInteger tildem_i;
  private BigInteger tildem_i_j;
  private Map<URN, BaseRepresentation> edgesPrime;
  private Map<URN, BaseRepresentation> verticesPrime;
  private List<BigInteger> challengeList = new ArrayList<BigInteger>();
  private Map<URN, BaseRepresentation> encodedBases;
  private Map<String, BigInteger> edgeBases;
  private BigInteger tildeU;
  private BigInteger cChallenge;
  private BigInteger m_0;
  private Map<String, BigInteger> vertexResponses;
  private Map<String, BigInteger> edgeResponses;
  private ProofObject proofObject;
  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private BigInteger hatm_i;
  private BigInteger hatm_i_j;

  /**
   * Instantiates a new Commitment prover.
   *  @param commitment the commitment
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
      ExtendedPublicKey extendedPublicKey) {

    this.commitment = commitment;
    this.vPrime = vPrime;
    this.R_0 = R_0;
    this.m_0 = m_0;
    this.nonce = nonce;
    this.keyGenParameters = keyGenParameters;
    this.extendedPublicKey = extendedPublicKey;
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

    GroupElement qrElementN = null; // = new QRElementN();
    BigInteger R_0tildem_0;
    R_0tildem_0 = R_0.modPow(tildem_0, extendedPublicKey.getPublicKey().getModN()).getValue();

    List<BigInteger> bases = new ArrayList<>();
    List<BigInteger> exponents = new ArrayList<>();
    bases.add(R_0.getValue());
    exponents.add(tildem_0);

    for (Map.Entry<URN, BaseRepresentation> base : verticesPrime.entrySet()) {
      bases.add(base.getValue().getBase().getValue());
      exponents.add(base.getValue().getExponent());
    }
    for (Map.Entry<URN, BaseRepresentation> edgeBase : edgesPrime.entrySet()) {
      bases.add(edgeBase.getValue().getBase().getValue());
      exponents.add(edgeBase.getValue().getExponent());
    }

    bases.add(extendedPublicKey.getPublicKey().getBaseS().getValue());
    exponents.add(tildevPrime);

    tildeU = qrElementN.multiBaseExp(bases, exponents);
  }

  @Override
  public BigInteger computeChallenge() {
    challengeList = populateChallengeList();
    cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  private List<BigInteger> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    //    R = extendedPublicKey.getPublicKey().getBasesR();
    //    R_0 = extendedPublicKey.getPublicKey().getBaseR_0();

    encodedBases = extendedPublicKey.getBases();

    challengeList.add(extendedPublicKey.getPublicKey().getModN());
    challengeList.add(extendedPublicKey.getPublicKey().getBaseS().getValue());
    challengeList.add(extendedPublicKey.getPublicKey().getBaseZ().getValue());
    //    challengeList.add(R);
    challengeList.add(R_0.getValue());

    /** TODO check bases */
    for (int i = 1; i <= encodedBases.size(); i++) {
      challengeList.add(encodedBases.get(URN.createZkpgsURN("R_" + i)).getBase().getValue());
    }
    /** TODO fix edge bases. use the bases map for edge bases */
    for (int j = 1; j <= edgeBases.size(); j++) {
      challengeList.add(edgeBases.get("R_" + j));
    }

    challengeList.add(commitment.getCommitment());
    challengeList.add(tildeU);
    challengeList.add(nonce);

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
