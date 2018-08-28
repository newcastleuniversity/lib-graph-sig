package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** The type Group setup prover. */
public class GroupSetupProver implements IProver {

  public static final String URNID = "groupsetupprover";

  private final ExtendedKeyPair extendedKeyPair;
  private ExtendedPublicKey ePublicKey;
  private BigInteger r_Z;
  private BigInteger r;
  private BigInteger r_0;
  private BigInteger tilder_Z;
  private BigInteger tilder;
  private BigInteger tilder_0;
  private GroupElement tildeZ;
  private GroupElement basetildeR;
  private GroupElement basetildeR_0;
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
  private final ProofStore<Object> proofStore;
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private Map<String, BigInteger> vertexWitnessRandomNumbers;
  private Map<String, BigInteger> vertexWitnessBases;
  private Map<String, BigInteger> edgeWitnessRandomNumbers;
  private Map<String, BigInteger> edgeWitnessBases;
  private Map<URN, BigInteger> vertexResponses;
  private Map<URN, BigInteger> edgeResponses;
  private BaseCollection baseRepresentationMap;
  private Map<String, BigInteger> edgeBases;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger hatr_i;
  private BigInteger tilder_i;
  private BigInteger tilder_j;
  private BigInteger hatr_j;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private BaseCollection baseCollection;

  public GroupSetupProver(ExtendedKeyPair extendedKeyPair, ProofStore ps) {
    Assert.notNull(extendedKeyPair, "Extended key pair must not be null");
    Assert.notNull(ps, "Proof store must not be null");

    this.extendedKeyPair = extendedKeyPair;
    this.extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
    this.baseS = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseS();
    this.modN = extendedKeyPair.getPublicKey().getModN();
    this.baseZ = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseZ();
    this.baseR = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseR();
    this.baseR_0 = (QRElementPQ) extendedKeyPair.getPublicKey().getBaseR_0();
    this.proofStore = ps;
    this.keyGenParameters = extendedKeyPair.getExtendedPublicKey().getKeyGenParameters();
    this.graphEncodingParameters =
        extendedKeyPair.getExtendedPublicKey().getGraphEncodingParameters();
    this.baseCollection = extendedKeyPair.getExtendedPublicKey().getBaseCollection();
  }

  @Override
  public void executePrecomputation() {
    // NO PRE-COMPUTATION IS NEEDED: NO-OP.
  }
  // TODO return multiple witnesses
  @Override
  public Map<URN, GroupElement> executePreChallengePhase() throws ProofStoreException {
    createWitnessRandomness();
    return computeWitnesses();
  }

  private void createWitnessRandomness() throws ProofStoreException {
    bitLength = computeBitlength();
    tilder_Z = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);

    tilder = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
    tilder_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);

    proofStore.store(getProverURN(URNType.TILDER), tilder);

    proofStore.store(getProverURN(URNType.TILDER0), tilder_0);

    proofStore.store(getProverURN(URNType.TILDERZ), tilder_Z);

    BigInteger vWitnessRandomness;
    BigInteger eWitnessRandomness;

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      vWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
      proofStore.store(
          getProverURN(URNType.TILDERI, baseRepresentation.getBaseIndex()), vWitnessRandomness);
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      eWitnessRandomness = CryptoUtilsFacade.computeRandomNumberMinusPlus(bitLength);
      proofStore.store(
          getProverURN(URNType.TILDERIJ, baseRepresentation.getBaseIndex()), eWitnessRandomness);
    }
  }

  private Map<URN, GroupElement> computeWitnesses() throws ProofStoreException {
    Map<URN, GroupElement> witnesses = new HashMap<URN, GroupElement>();
    tildeZ = baseS.modPow(tilder_Z);
    basetildeR = baseS.modPow(tilder);
    basetildeR_0 = baseS.modPow(tilder_0);

    proofStore.store(getProverURN(URNType.TILDEBASEZ), tildeZ);
    witnesses.put(URN.createZkpgsURN(getProverURN(URNType.TILDEBASEZ)), tildeZ);

    proofStore.store(getProverURN(URNType.TILDEBASER), basetildeR);
    witnesses.put(URN.createZkpgsURN(getProverURN(URNType.TILDEBASER)), basetildeR);
    proofStore.store(getProverURN(URNType.TILDEBASER0), basetildeR_0);
    witnesses.put(URN.createZkpgsURN(getProverURN(URNType.TILDEBASER0)), basetildeR_0);

    GroupElement vWitnessBase;
    GroupElement eWitnessBase;
    BigInteger vWitnessRandomNumber;
    BigInteger eWitnessRandomNumber;

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      vWitnessRandomNumber =
          (BigInteger)
              proofStore.retrieve(getProverURN(URNType.TILDERI, baseRepresentation.getBaseIndex()));

      vWitnessBase = baseS.modPow(vWitnessRandomNumber);
      proofStore.store(
          getProverURN(URNType.TILDEBASERI, baseRepresentation.getBaseIndex()), vWitnessBase);
      witnesses.put(
          URN.createZkpgsURN(getProverURN(URNType.TILDEBASERI, baseRepresentation.getBaseIndex())),
          vWitnessBase);
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      eWitnessRandomNumber =
          (BigInteger)
              proofStore.retrieve(
                  getProverURN(URNType.TILDERIJ, baseRepresentation.getBaseIndex()));
      eWitnessBase = baseS.modPow(eWitnessRandomNumber);
      proofStore.store(
          getProverURN(URNType.TILDEBASERIJ, baseRepresentation.getBaseIndex()), eWitnessBase);
      witnesses.put(
          URN.createZkpgsURN(getProverURN(URNType.TILDEBASERIJ, baseRepresentation.getBaseIndex())),
          eWitnessBase);
    }
    return witnesses;
  }

  /**
   * Post challenge phase.
   *
   * @throws ProofStoreException the proof store exception
   */
  @Override
  public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge)
      throws ProofStoreException {

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
    Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>();
    this.cChallenge = cChallenge;

    hatr_Z = tilder_Z.add(cChallenge.multiply(r_Z));
    hatr = tilder.add(cChallenge.multiply(r));
    hatr_0 = tilder_0.add(cChallenge.multiply(r_0));

    proofStore.store(getProverURN(URNType.HATRZ), hatr_Z);
    proofStore.store(getProverURN(URNType.HATR), hatr);
    proofStore.store(getProverURN(URNType.HATR0), hatr_0);

    /** TODO check r_i, r_j computations */
    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      r_i =
          discLogs.get(
              URN.createZkpgsURN("discretelogs.vertex.R_i_" + baseRepresentation.getBaseIndex()));
      tilder_i =
          (BigInteger)
              proofStore.retrieve(getProverURN(URNType.TILDERI, baseRepresentation.getBaseIndex()));

      hatr_i = tilder_i.add(cChallenge.multiply(r_i));

      URN urn = URN.createZkpgsURN(getProverURN(URNType.HATRI, baseRepresentation.getBaseIndex()));
      vertexResponses.put(urn, hatr_i);
      responses.put(urn, hatr_i);

      proofStore.save(urn, hatr_i);
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      r_j =
          discLogs.get(
              URN.createZkpgsURN("discretelogs.edge.R_i_j_" + baseRepresentation.getBaseIndex()));
      tilder_j =
          (BigInteger)
              proofStore.retrieve(
                  getProverURN(URNType.TILDERIJ, baseRepresentation.getBaseIndex()));

      hatr_j = tilder_j.add(cChallenge.multiply(r_j));

      URN urn = URN.createZkpgsURN(getProverURN(URNType.HATRIJ, baseRepresentation.getBaseIndex()));
      edgeResponses.put(urn, hatr_j);
      responses.put(urn, hatr_j);

      proofStore.save(urn, hatr_j);
    }
    return responses;
  }

  private int computeBitlength() {
    return keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
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

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      proofSignatureElements.put(
          URN.createZkpgsURN("proofsignature.P.R_i_" + baseRepresentation.getBaseIndex()),
          baseRepresentation);
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      proofSignatureElements.put(
          URN.createZkpgsURN("proofsignature.P.R_i_j_" + baseRepresentation.getBaseIndex()),
          baseRepresentation);
    }

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_Z"), this.hatr_Z);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr"), this.hatr);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_0"), this.hatr_0);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i"), this.vertexResponses);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i_j"), this.edgeResponses);
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.c"), cChallenge);

    return new ProofSignature(proofSignatureElements);
  }

  public boolean isSetupComplete() {
    return false;
  }

  @Override
  public boolean verify() {
    return false;
  }

  public String getProverURN(URNType t) {
    if (URNType.isEnumerable(t)) {
      throw new RuntimeException(
          "URNType " + t + " is enumerable and should be evaluated with an index.");
    }
    return GroupSetupProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t);
  }

  public String getProverURN(URNType t, int index) {
    if (!URNType.isEnumerable(t)) {
      throw new RuntimeException(
          "URNType " + t + " is not enumerable and should not be evaluated with an index.");
    }
    return GroupSetupProver.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t) + index;
  }

  public List<URN> getGovernedURNs() {
    throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
}
