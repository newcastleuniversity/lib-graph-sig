package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/** The type Group setup prover. */
public class GroupSetupProver implements IProver {

  public static final String URNID = "groupsetupprover";
  private final ExtendedKeyPair extendedKeyPair;
  private BigInteger tilder_Z;
  private BigInteger tilder;
  private BigInteger tilder_0;
  private BigInteger hatr_Z;
  private BigInteger hatr;
  private BigInteger hatr_0;
  private GroupElement baseS;
  private BigInteger modN;
  private GroupElement baseZ;
  private BigInteger cChallenge;
  private GroupElement baseR;
  private GroupElement baseR_0;
  private final ProofStore<Object> proofStore;
  private KeyGenParameters keyGenParameters;
  private Map<URN, BigInteger> vertexResponses;
  private Map<URN, BigInteger> edgeResponses;

  private BaseCollection baseCollection;

  public GroupSetupProver(ExtendedKeyPair extendedKeyPair, ProofStore<Object> ps) {
    Assert.notNull(extendedKeyPair, "Extended key pair must not be null");
    Assert.notNull(ps, "Proof store must not be null");

    this.extendedKeyPair = extendedKeyPair;
    this.baseS = extendedKeyPair.getPublicKey().getBaseS();
    this.modN = extendedKeyPair.getPublicKey().getModN();
    this.baseZ = extendedKeyPair.getPublicKey().getBaseZ();
    this.baseR = extendedKeyPair.getPublicKey().getBaseR();
    this.baseR_0 = extendedKeyPair.getPublicKey().getBaseR_0();
    this.proofStore = ps;
    this.keyGenParameters = extendedKeyPair.getExtendedPublicKey().getKeyGenParameters();
    this.baseCollection = extendedKeyPair.getExtendedPublicKey().getBaseCollection();
  }

  @Override
  public void executePrecomputation() {
    // NO PRE-COMPUTATION IS NEEDED: NO-OP.
  }

  @Override
  public Map<URN, GroupElement> executeCompoundPreChallengePhase() throws ProofStoreException {
    createWitnessRandomness();
    return computeWitnesses();
  }

  /**
   * This method returns a single witness for Z, even though the prover creates a compound proof
   * with many witnesses.
   *
   * <p>All witnesses created are stored in the ProofStore as a side condition, under their
   * appropriate URNs. It is preferable to call executeCompoundPreChallengePhase().
   *
   * @return GroupElement witness tildeZ
   * @deprecated
   */
  @Override
  @Deprecated
  public GroupElement executePreChallengePhase() throws ProofStoreException {
    createWitnessRandomness();
    Map<URN, GroupElement> witnesses = computeWitnesses();
    return witnesses.get(URN.createZkpgsURN(getProverURN(URNType.TILDEBASEZ)));
  }

  private void createWitnessRandomness() throws ProofStoreException {
    int bitLength = computeBitlength();
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
    GroupElement tildeZ = baseS.modPow(tilder_Z);
    GroupElement basetildeR = baseS.modPow(tilder);
    GroupElement basetildeR_0 = baseS.modPow(tilder_0);

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
    BigInteger r_i;
    BigInteger r_j;
    Map<URN, BigInteger> discLogs = extendedKeyPair.getExtendedPrivateKey().getDiscLogOfBases();
    Map<URN, BigInteger> responses = new HashMap<URN, BigInteger>();
    vertexResponses = new HashMap<>();
    edgeResponses = new HashMap<>();
    this.cChallenge = cChallenge;

    hatr_Z = tilder_Z.add(cChallenge.multiply(r_Z));
    hatr = tilder.add(cChallenge.multiply(r));
    hatr_0 = tilder_0.add(cChallenge.multiply(r_0));

    proofStore.store(getProverURN(URNType.HATRZ), hatr_Z);
    responses.put(URN.createZkpgsURN(getProverURN(URNType.HATRZ)), hatr_Z);

    proofStore.store(getProverURN(URNType.HATR), hatr);
    responses.put(URN.createZkpgsURN(getProverURN(URNType.HATR)), hatr);

    proofStore.store(getProverURN(URNType.HATR0), hatr_0);
    responses.put(URN.createZkpgsURN(getProverURN(URNType.HATR0)), hatr_0);

    BigInteger hatr_i;
    BigInteger tilder_i;
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

      URN hatr_iURN =
          URN.createZkpgsURN(getProverURN(URNType.HATRI, baseRepresentation.getBaseIndex()));
      responses.put(hatr_iURN, hatr_i);
      vertexResponses.put(hatr_iURN, hatr_i);
      proofStore.save(hatr_iURN, hatr_i);
    }

    BigInteger tilder_j;
    BigInteger hatr_j;
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

      URN hatr_i_jURN =
          URN.createZkpgsURN(getProverURN(URNType.HATRIJ, baseRepresentation.getBaseIndex()));
      responses.put(hatr_i_jURN, hatr_j);
      edgeResponses.put(hatr_i_jURN, hatr_j);
      proofStore.save(hatr_i_jURN, hatr_j);
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

  @Override
public List<URN> getGovernedURNs() {
    throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
}
