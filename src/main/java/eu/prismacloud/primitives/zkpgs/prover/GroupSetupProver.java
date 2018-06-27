package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/** */
public class GroupSetupProver implements IProver, Storable {

  private ExtendedKeyPair extendedKeyPair;
  private ExtendedPublicKey ePublicKey;
  private BigInteger r_Z;
  private BigInteger r;
  private BigInteger r_0;
  private BigInteger tilder_Z;
  private BigInteger tilder;
  private BigInteger tilder_0;
  private BigInteger tildeZ;
  private BigInteger tildeR;
  private BigInteger tildeR_0;
  private BigInteger hatr_Z;
  private BigInteger hatr;
  private BigInteger hatr_0;
  private Iterator<GSVertex> gsVertexIterator;
  private Iterator<GSEdge> gsEdgeIterator;
  private List<GSVertex> gsVertices;
  private List<GSEdge> gsEdges;
  private int bitLength;
  private GroupElement baseS;
  private BigInteger modN;
  private GroupElement baseZ;
  private BigInteger cChallenge;
  private GroupElement baseR;
  private GroupElement baseR_0;
  private List<BigInteger> challengeList = new ArrayList<BigInteger>();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private Map<String, BigInteger> vertexWitnessRandomNumbers;
  private Map<String, BigInteger> vertexWitnessBases;
  private Map<String, BigInteger> edgeWitnessRandomNumbers;
  private Map<String, BigInteger> edgeWitnessBases;
  private Map<String, BigInteger> vertexResponses;
  private Map<String, BigInteger> edgeResponses;
  private Map<URN, BaseRepresentation> bases;
  private Map<String, BigInteger> edgeBases;

  public GroupSetupProver(
      final GroupElement baseS,
      final BigInteger modN,
      final GroupElement baseZ,
      final KeyGenParameters keyGenParameters) {
    this.baseS = baseS;
    this.modN = modN;
    this.baseZ = baseZ;
    this.keyGenParameters = keyGenParameters;
  }

  public GroupSetupProver(
      final ExtendedKeyPair extendedKeyPair,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {
    this.extendedKeyPair = extendedKeyPair;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
  }

  public GroupSetupProver() {

  }

  @Override
  public void createWitnessRandomness() {
    bitLength = computeBitlength();
    tilder_Z = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
    tilder = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
    tilder_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
    BigInteger vWitnessRandomness;
    BigInteger eWitnessRandomness;

    for (int i = 1; i <= graphEncodingParameters.getL_V(); i++) {
      vWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
      vertexWitnessRandomNumbers.put("tilder_" + i, vWitnessRandomness);
    }

    for (int j = 1; j <= graphEncodingParameters.getL_E(); j++) {
      eWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
      edgeWitnessRandomNumbers.put("tilder_" + j, eWitnessRandomness);
    }
  }

  @Override
  public void computeWitness() {
    tildeZ = baseS.modPow(tilder_Z, modN).getValue();
    tildeR = baseS.modPow(tilder, modN).getValue();
    tildeR_0 = baseS.modPow(tildeR_0, modN).getValue();
    BigInteger vWitnessBase;
    BigInteger eWitnessBase;
    BigInteger vWitnessRandomNumber;
    BigInteger eWitnessRandomNumber;

    for (int i = 1; i <= graphEncodingParameters.getL_V(); i++) {
      vWitnessRandomNumber = vertexWitnessRandomNumbers.get("tilder_" + i);
      vWitnessBase = baseS.modPow(vWitnessRandomNumber, modN).getValue();
      vertexWitnessRandomNumbers.put("tildeR_" + i, vWitnessBase);
    }

    for (int j = 1; j <= graphEncodingParameters.getL_E(); j++) {
      eWitnessRandomNumber = edgeWitnessRandomNumbers.get("tilder_" + j);
      eWitnessBase = baseS.modPow(eWitnessRandomNumber, modN).getValue();
      vertexWitnessRandomNumbers.put("tildeR_" + j, eWitnessBase);
    }
  }

  @Override
  public BigInteger computeChallenge() {
    challengeList = populateChallengeList();
    cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  @Override
  public void computeResponses() {
    BigInteger r_Z = extendedKeyPair.getPrivateKey().getX_rZ();
    BigInteger r = extendedKeyPair.getPrivateKey().getX_r();
    BigInteger r_0 = extendedKeyPair.getPrivateKey().getX_r0();
    BigInteger witnessRandomness;
    BigInteger vertexResponse;
    BigInteger r_i;
    BigInteger r_j;
    BigInteger edgeResponse;
    vertexResponses = new HashMap<String, BigInteger>();
    edgeResponses = new HashMap<String, BigInteger>();

    hatr_Z = tilder_Z.add(cChallenge.multiply(r_Z));
    hatr = tilder.add(cChallenge.multiply(r));
    hatr_0 = tilder_0.add(cChallenge.multiply(r_0));

    /** TODO check r_i, r_j computations */
    for (int i = 1; i <= graphEncodingParameters.getL_V(); i++) {
      r_i =
          extendedKeyPair
              .getPublicKey()
              .getBases()
              .get(URN.createZkpgsURN("r_" + i))
              .getExponent();
      witnessRandomness = vertexWitnessRandomNumbers.get("tilder_" + i);
      vertexResponse = witnessRandomness.add(cChallenge.multiply(r_i));
      vertexResponses.put("hatr_" + i, vertexResponse);
    }

    for (int j = 1; j <= graphEncodingParameters.getL_E(); j++) {
      r_j =
          extendedKeyPair
              .getPublicKey()
              .getBases()
              .get(URN.createZkpgsURN("r_" + j))
              .getExponent();
      witnessRandomness = edgeWitnessRandomNumbers.get("tilder_" + j);
      edgeResponse = witnessRandomness.add(cChallenge.multiply(r_j));
      edgeResponses.put("hatr" + j, edgeResponse);
    }
  }

  private int computeBitlength() {
    return keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
  }

  private List<BigInteger> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    baseR = extendedKeyPair.getPublicKey().getBaseR();
    baseR_0 = extendedKeyPair.getPublicKey().getBaseR_0();
    bases = extendedKeyPair.getPublicKey().getBases();

    challengeList.add(modN);
    challengeList.add(baseS.getValue());
    challengeList.add(baseZ.getValue());
    challengeList.add(baseR.getValue());
    challengeList.add(baseR_0.getValue());

    for (BaseRepresentation baseRepresentation : bases.values()) {
      challengeList.add(baseRepresentation.getBase().getValue());
    }

    challengeList.add(tildeZ);
    challengeList.add(tildeR);
    challengeList.add(tildeR_0);

    /** TODO use URNs for keys in witnesses bases */
    for (int i = 1; i <= vertexWitnessBases.size(); i++) {
      challengeList.add(vertexWitnessBases.get("tildeR_" + i));
    }

    for (int j = 1; j <= edgeWitnessBases.size(); j++) {
      challengeList.add(edgeWitnessBases.get("tildeR_" + j));
    }
    return challengeList;
  }

  public ProofSignature outputProofSignature() {

    Map<URN, Object> proofSignatureElements = new HashMap<>();

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.modN"), this.modN);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseS"), this.baseS);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseZ"), this.baseZ);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseR"), this.baseR);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseR_0"), this.baseR_0);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.R_i"), this.bases);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.R_i_j"), this.edgeBases);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_Z"), this.hatr_Z);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr"), this.hatr);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_0"), this.hatr_0);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i"), this.vertexResponses);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i_j"), this.edgeResponses);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.c"), cChallenge);

    return new ProofSignature(proofSignatureElements);
  }

  @Override
  public void store(URN urn, ProofObject proofObject) {}

  @Override
  public ProofObject retrieve(URN urn) {
    return null;
  }
}
