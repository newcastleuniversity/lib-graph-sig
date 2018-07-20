package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Group setup prover. */
public class GroupSetupProver implements IProver {

  private ExtendedKeyPair extendedKeyPair;
  private ExtendedPublicKey ePublicKey;
  private BigInteger r_Z;
  private BigInteger r;
  private BigInteger r_0;
  private BigInteger tilder_Z;
  private BigInteger tilder;
  private BigInteger tilder_0;
  private BigInteger tildeZ;
  private BigInteger basetildeR;
  private BigInteger basetildeR_0;
  private BigInteger hatr_Z;
  private BigInteger hatr;
  private BigInteger hatr_0;
  private int bitLength;
  private QRElementPQ baseS;
  private BigInteger modN;
  private QRElementPQ baseZ;
  private BigInteger cChallenge;
  private QRElementPQ baseR;
  private QRElementPQ baseR_0;
  private List<String> challengeList = new ArrayList<String>();
  private ProofStore<Object> proofStore;
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private Map<String, BigInteger> vertexWitnessRandomNumbers;
  private Map<String, BigInteger> vertexWitnessBases;
  private Map<String, BigInteger> edgeWitnessRandomNumbers;
  private Map<String, BigInteger> edgeWitnessBases;
  private HashMap<URN, BigInteger> vertexResponses;
  private HashMap<URN, BigInteger> edgeResponses;
  private Map<URN, BaseRepresentation> baseRepresentationMap;
  private Map<String, BigInteger> edgeBases;
  private List<String> contextList;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger hatr_i;
  private BigInteger tilder_i;
  private BigInteger tilder_j;
  private BigInteger hatr_j;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  /**
   * Pre challenge phase.
   *
   * @param extendedKeyPair the extended public key
   * @param proofStore the proof store
   * @param keyGenParameters the key gen parameters
   * @param graphEncodingParameters the graph encoding parameters
   */
  public void preChallengePhase(
      final ExtendedKeyPair extendedKeyPair,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    this.extendedKeyPair = extendedKeyPair;
    this.extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
    this.baseS = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseS();
    this.modN = extendedKeyPair.getPublicKey().getModN();
    this.baseZ = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseZ();
    this.baseR = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseR();
    this.baseR_0 = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseR_0();
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.baseRepresentationMap = extendedKeyPair.getExtendedPublicKey().getBases();

    try {
      createWitnessRandomness();
      computeWitness();
    } catch (ProofStoreException e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  public void preChallengePhase(
      final ExtendedPublicKey extendedPublicKey,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    this.extendedPublicKey = extendedPublicKey;
    this.baseS = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseS();
    this.modN = extendedKeyPair.getPublicKey().getModN();
    this.baseZ = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseZ();
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.baseRepresentationMap = extendedKeyPair.getExtendedPublicKey().getBases();

    try {
      createWitnessRandomness();
      computeWitness();
    } catch (ProofStoreException e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  //  @Override
  public void createWitnessRandomness() throws ProofStoreException {
    bitLength = computeBitlength();
    tilder_Z = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);

    tilder = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
    tilder_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);

    proofStore.store("groupsetupprover.witnesses.randomness.tilder", tilder);

    proofStore.store("groupsetupprover.witnesses.randomness.tilder_0", tilder_0);

    proofStore.store("groupsetupprover.witnesses.randomness.tilder_Z", tilder_Z);

    BigInteger vWitnessRandomness;
    BigInteger eWitnessRandomness;

    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
      if (baseRepresentation.getBaseType() == BASE.VERTEX) {

        vWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
        //        vertexWitnessRandomNumbers.put(
        //            "tilder_" + baseRepresentation.getBaseIndex(), vWitnessRandomness);

        proofStore.store(
            "groupsetupprover.witnesses.randomness.tilder_i_" + baseRepresentation.getBaseIndex(),
            vWitnessRandomness);

      } else if (baseRepresentation.getBaseType() == BASE.EDGE) {

        eWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
        //        edgeWitnessRandomNumbers.put(
        //            "tilder_" + baseRepresentation.getBaseIndex(), eWitnessRandomness);
        proofStore.store(
            "groupsetupprover.witnesses.randomness.tilder_j_" + baseRepresentation.getBaseIndex(),
            eWitnessRandomness);
      }
    }
  }

  //  @Override
  public void computeWitness() throws ProofStoreException {
    tildeZ = baseS.modPow(tilder_Z).getValue();
    basetildeR = baseS.modPow(tilder).getValue();
    basetildeR_0 = baseS.modPow(tilder_0).getValue();

    proofStore.store("groupsetupprover.witnesses.tildeZ", tildeZ);

    proofStore.store("groupsetupprover.witnesses.tildeR", basetildeR);

    proofStore.store("groupsetupprover.witnesses.tildeR_0", basetildeR_0);

    BigInteger vWitnessBase;
    BigInteger eWitnessBase;
    BigInteger vWitnessRandomNumber;
    BigInteger eWitnessRandomNumber;

    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
      if (baseRepresentation.getBaseType() == BASE.VERTEX) {

        vWitnessRandomNumber =
            (BigInteger)
                proofStore.retrieve(
                    "groupsetupprover.witnesses.randomness.tilder_i_"
                        + baseRepresentation.getBaseIndex());

        vWitnessBase = baseS.modPow(vWitnessRandomNumber).getValue();
        //        vertexWitnessRandomNumbers.put("tildeR_" + baseRepresentation.getBaseIndex(),
        // vWitnessBase);

        proofStore.store(
            "groupsetupprover.witnesses.tildeR_i_" + baseRepresentation.getBaseIndex(),
            vWitnessBase);

      } else if (baseRepresentation.getBaseType() == BASE.EDGE) {

        eWitnessRandomNumber =
            (BigInteger)
                proofStore.retrieve(
                    "groupsetupprover.witnesses.randomness.tilder_j_"
                        + baseRepresentation.getBaseIndex());
        eWitnessBase = baseS.modPow(eWitnessRandomNumber).getValue();
        //        vertexWitnessRandomNumbers.put("tildeR_" + baseRepresentation.getBaseIndex(),
        // eWitnessBase);
        proofStore.store(
            "groupsetupprover.witnesses.tildeR_j_" + baseRepresentation.getBaseIndex(),
            eWitnessBase);
      }
    }
  }

  //  @Override
  public BigInteger computeChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
    return cChallenge;
  }

  @Override
  public void computeResponses() {}

  /**
   * Post challenge phase.
   *
   * @throws ProofStoreException the proof store exception
   */
  //  @Override
  public void postChallengePhase() throws ProofStoreException {

    BigInteger r_Z = extendedKeyPair.getPrivateKey().getX_rZ();
    BigInteger r = extendedKeyPair.getPrivateKey().getX_r();
    BigInteger r_0 = extendedKeyPair.getPrivateKey().getX_r0();
    BigInteger witnessRandomness;
    BigInteger vertexResponse;
    BigInteger r_i;
    BigInteger r_j;
    BigInteger edgeResponse;
    Map<URN, BigInteger> discLogs = extendedKeyPair.getExtendedPrivateKey().getDiscLogOfBases();

    vertexResponses = new HashMap<URN, BigInteger>();
    edgeResponses = new HashMap<URN, BigInteger>();

    hatr_Z = tilder_Z.add(cChallenge.multiply(r_Z));
    hatr = tilder.add(cChallenge.multiply(r));
    hatr_0 = tilder_0.add(cChallenge.multiply(r_0));

    proofStore.store("groupsetupprover.responses.hatr_Z", hatr_Z);
    proofStore.store("groupsetupprover.responses.hatr", hatr);
    proofStore.store("groupsetupprover.responses.hatr_0", hatr_0);

    /** TODO check r_i, r_j computations */
    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
      if (baseRepresentation.getBaseType() == BASE.VERTEX) {

        r_i =
            discLogs.get(
                URN.createZkpgsURN("discretelogs.vertex.R_i_" + baseRepresentation.getBaseIndex()));
        tilder_i =
            (BigInteger)
                proofStore.retrieve(
                    "groupsetupprover.witnesses.randomness.tilder_i_"
                        + baseRepresentation.getBaseIndex());

        hatr_i = tilder_i.add(cChallenge.multiply(r_i));

        vertexResponses.put(
            URN.createZkpgsURN(
                "groupsetupprover.responses.hatr_i_" + baseRepresentation.getBaseIndex()),
            hatr_i);

        proofStore.store(
            "groupsetupprover.responses.hatr_i_" + baseRepresentation.getBaseIndex(), hatr_i);

      } else if (baseRepresentation.getBaseType() == BASE.EDGE) {
        r_j =
            discLogs.get(
                URN.createZkpgsURN("discretelogs.edge.R_i_j_" + baseRepresentation.getBaseIndex()));
        tilder_j =
            (BigInteger)
                proofStore.retrieve(
                    "groupsetupprover.witnesses.randomness.tilder_j_"
                        + baseRepresentation.getBaseIndex());

        hatr_j = tilder_j.add(cChallenge.multiply(r_j));

        edgeResponses.put(
            URN.createZkpgsURN(
                "groupsetupprover.responses.hatr_i_j_" + baseRepresentation.getBaseIndex()),
            hatr_j);

        proofStore.store(
            "groupsetupprover.responses.hatr_j_" + baseRepresentation.getBaseIndex(), hatr_j);
      }
    }
  }

  private int computeBitlength() {
    return keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
  }

  private List<String> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    GSContext gsContext =
                new GSContext(extendedPublicKey, keyGenParameters, graphEncodingParameters);
        List<String> contextList = gsContext.computeChallengeContext();

    //    baseR = extendedPublicKey.getPublicKey().getBaseR();
    //    baseR_0 = extendedPublicKey.getPublicKey().getBaseR_0();
    baseRepresentationMap = extendedPublicKey.getBases();

    challengeList.add(String.valueOf(modN));
    challengeList.add(String.valueOf(baseS.getValue()));
    challengeList.add(String.valueOf(baseZ.getValue()));
    challengeList.add(String.valueOf(baseR.getValue()));
    challengeList.add(String.valueOf(baseR_0.getValue()));

    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
    }

    challengeList.add(String.valueOf(tildeZ));
    challengeList.add(String.valueOf(basetildeR));
    challengeList.add(String.valueOf(basetildeR_0));

    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
      if (baseRepresentation.getBaseType() == BASE.VERTEX) {

        tilder_i =
            (BigInteger)
                proofStore.retrieve(
                    "groupsetupprover.witnesses.tildeR_i_"
                        + baseRepresentation.getBaseIndex());
        challengeList.add(String.valueOf(tilder_i));

      } else if (baseRepresentation.getBaseType() == BASE.EDGE) {
        tilder_j =
            (BigInteger)
                proofStore.retrieve(
                    "groupsetupprover.witnesses.tildeR_j_"
                        + baseRepresentation.getBaseIndex());
        challengeList.add(String.valueOf(tilder_j));
      }
    }

    return challengeList;
  }

  /**
   * Output proof signature proof signature.
   *
   * @return the proof signature
   */
  public ProofSignature outputProofSignature() {

    Map<URN, Object> proofSignatureElements = new HashMap<>();

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.modN"), this.modN);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseS"), this.baseS);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseZ"), this.baseZ);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseR"), this.baseR);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.baseR_0"), this.baseR_0);
    BaseRepresentation baseR;
    for (Entry<URN, BaseRepresentation> baseRepresentation : baseRepresentationMap.entrySet()) {

//      gslog.info("key: " + baseRepresentation.getKey());
      baseR = baseRepresentation.getValue();
      if (baseR.getBaseType() == BASE.VERTEX) {
        proofSignatureElements.put(
            URN.createZkpgsURN("proofsignature.P.R_i_" + baseR.getBaseIndex()), baseR);
      } else if (baseR.getBaseType() == BASE.EDGE) {
        proofSignatureElements.put(
            URN.createZkpgsURN("proofsignature.P.R_i_j_" + baseR.getBaseIndex()), baseR);
      }
    }

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_Z"), this.hatr_Z);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr"), this.hatr);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_0"), this.hatr_0);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i"), this.vertexResponses);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i_j"), this.edgeResponses);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.c"), cChallenge);

    return new ProofSignature(proofSignatureElements);
  }
}
