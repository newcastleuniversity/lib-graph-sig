package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PossessionProver implements IProver {

  private GSSignature blindedSignature;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger R_0;
  private BigInteger tildem_0;
  private BigInteger tildevPrime;
  private GraphRepresentation graphRepresentation;
  private ProofStore<Object> proverStore;
  private KeyGenParameters keyGenParameters;
  //  private Map<URN, BaseRepresentation> bases;
  //  private Map<URN, BaseRepresentation> edges;
  private BigInteger tildeZ;
  private BigInteger tildee;
  //  private Map<URN, BigInteger> vertexWitnesses;
  //  private Map<URN, BigInteger> edgeWitnesses;
  private BigInteger tildem_i;
  private BigInteger tildem_i_j;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private BigInteger c;
  private int baseIndex;
  private BaseCollection baseCollection;
  private BaseIterator vertexIterator;
  private BaseIterator edgeIterator;
  private BaseIterator baseIterator;
  private BigInteger tildev;
  private GroupElement baseS;
  private GroupElement baseR_0;

  public GroupElement preChallengePhase(
      GSSignature blindedSignature,
      ExtendedPublicKey extendedPublicKey,
      BaseCollection baseCollection,
      ProofStore<Object> proverStore,
      KeyGenParameters keyGenParameters) {
    Assert.notNull(blindedSignature, "blinded graph signature must not be null");
    Assert.notNull(extendedPublicKey, "extended public key must not be null");
    Assert.notNull(baseCollection, "encoded bases collection must not be null");
    Assert.notNull(proverStore, "prover store must not be null");
    Assert.notNull(keyGenParameters, "keygen parameters must not be null");

    this.blindedSignature = blindedSignature;
    this.extendedPublicKey = extendedPublicKey;
    this.baseCollection = baseCollection;
    this.proverStore = proverStore;
    this.keyGenParameters = keyGenParameters;
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseR_0 = extendedPublicKey.getPublicKey().getBaseR_0();
    this.baseIterator = baseCollection.createIterator(BASE.ALL);
    this.vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    this.edgeIterator = baseCollection.createIterator(BASE.EDGE);

    try {
      createWitnessRandomness();
      storeWitnessRandomness();
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }

    return computetildeZ();
  }

  public BigInteger getTildeZ() {
    return this.tildeZ;
  }

  public void createWitnessRandomness() throws ProofStoreException {

    int tildeeLength =
        keyGenParameters.getL_prime_e()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_H()
            + 1;
    tildee = CryptoUtilsFacade.computeRandomNumber(tildeeLength);

    int tildevLength =
        keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
    tildev = CryptoUtilsFacade.computeRandomNumber(tildevLength);

    int messageLength =
        keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

    tildem_0 = CryptoUtilsFacade.computeRandomNumber(messageLength);

    //    vertexWitnesses = new LinkedHashMap<>();
    //    edgeWitnesses = new LinkedHashMap<>();
    String witnessRandomnessURN = "";

    for (BaseRepresentation base : vertexIterator) {
      tildem_i = CryptoUtilsFacade.computeRandomNumber(messageLength);
      witnessRandomnessURN =
          "possessionprover.witnesses.randomness.vertex.tildem_i_" + base.getBaseIndex();
      //      vertexWitnesses.put(URN.createZkpgsURN(witnessRandomnessURN), tildem_i);
      proverStore.store(witnessRandomnessURN, tildem_i);
    }

    for (BaseRepresentation base : edgeIterator) {
      tildem_i_j = CryptoUtilsFacade.computeRandomNumber(messageLength);
      witnessRandomnessURN =
          "possessionprover.witnesses.randomness.edge.tildem_i_j_" + base.getBaseIndex();
      //      edgeWitnesses.put(URN.createZkpgsURN(witnessRandomnessURN), tildem_i_j);
      proverStore.store(witnessRandomnessURN, tildem_i_j);
    }
  }

  private void storeWitnessRandomness() throws Exception {
    String tildeeURN = "possessionprover.witnesses.randomness.tildee";
    proverStore.store(tildeeURN, tildee);

    /** TODO check if it is tildev or tildevPrime */
    String tildevURN = "possessionprover.witnesses.randomness.tildev";
    proverStore.store(tildevURN, tildev);

    String tildem_0URN = "possessionprover.witnesses.randomness.tildem_0";
    proverStore.store(tildem_0URN, tildem_0);

    //    String tildem_iURN = "possessionprover.witnesses.randomness.tildem_i";
    //    proverStore.store(tildem_iURN, vertexWitnesses);
    //
    //    String tildem_i_jURN = "possessionprover.witnesses.randomness.tildem_i_j";
    //    proverStore.store(tildem_i_jURN, edgeWitnesses);
  }

  public void computeWitness() {}

  //  @Override
  public GroupElement computetildeZ() {

    GroupElement aPrimeEtilde = blindedSignature.getA().modPow(tildee);
    /** TODO check if tildev or tildevprime */
    GroupElement sTildeVPrime = baseS.modPow(tildev);
    GroupElement baseProduct = extendedPublicKey.getPublicKey().getQRGroup().getOne();

    String tildemURN = "";
    BigInteger vertexWitness = BigInteger.ONE;
    BigInteger edgeWitness = BigInteger.ONE;

    for (BaseRepresentation baseRepresentation : vertexIterator) {
      tildemURN =
          "possessionprover.witnesses.randomness.vertex.tildem_i_"
              + baseRepresentation.getBaseIndex();
      vertexWitness = (BigInteger) proverStore.retrieve(tildemURN);
      //      vertexWitness = vertexWitnesses.get(URN.createZkpgsURN(baseURN));
      baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(vertexWitness));
    }

    for (BaseRepresentation baseRepresentation : edgeIterator) {
      tildemURN =
          "possessionprover.witnesses.randomness.edge.tildem_i_j_"
              + baseRepresentation.getBaseIndex();
      //      edgeWitness = edgeWitnesses.get(URN.createZkpgsURN(baseURN));
      edgeWitness = (BigInteger) proverStore.retrieve(tildemURN);
      baseProduct = baseProduct.multiply(baseRepresentation.getBase().modPow(edgeWitness));
    }

    String tildem_0URN = "possessionprover.witnesses.randomness.tildem_0";
    tildem_0 = (BigInteger) proverStore.retrieve(tildem_0URN);

    GroupElement baseR_0tildem_0 = baseR_0.modPow(tildem_0);
    baseProduct =
        baseProduct.multiply(aPrimeEtilde).multiply(sTildeVPrime).multiply(baseR_0tildem_0);

    //    tildeZ =
    //        CryptoUtilsFacade.computeMultiBaseExMap(
    //            bases, exponents, extendedPublicKey.getPublicKey().getModN());
    return baseProduct;
  }

  @Override
  public BigInteger computeChallenge() throws NoSuchAlgorithmException {
    return null;
  }

  public void setChallenge(BigInteger challenge) {
    this.c = challenge;
  }

  public void postChallengePhase(BigInteger cChallenge) {
    gslog.info("prover: post challenge phase");
    this.c = cChallenge;

    String ePrimeURN = "prover.blindedgs.ePrime";
    BigInteger ePrime = (BigInteger) proverStore.retrieve(ePrimeURN);

    String vPrimeURN = "prover.blindedgs.vPrime";
    BigInteger vPrime = (BigInteger) proverStore.retrieve(vPrimeURN);

    BaseIterator baseR0Iterator = baseCollection.createIterator(BASE.BASE0);
    BaseRepresentation baseRepR_0 = checkBaseR_0(baseR0Iterator);

    BigInteger m_0 = baseRepR_0.getExponent();

    BigInteger m_i;
    BigInteger hatm_i;
    String tildem_iURN;
    String tildem_iPath = "possessionprover.witnesses.randomness.vertex.tildem_i_";

    for (BaseRepresentation vertexBase : vertexIterator) {
      baseIndex = vertexBase.getBaseIndex();
      tildem_iURN = tildem_iPath + baseIndex;
      gslog.info("vertex m urn: " + tildem_iURN);
      m_i = vertexBase.getExponent();
      tildem_i = (BigInteger) proverStore.retrieve(tildem_iURN);
      hatm_i = tildem_i.add(this.c.multiply(m_i));

      String hatm_iURN = "possessionprover.responses.vertex.hatm_i_" + baseIndex;

      try {
        proverStore.store(hatm_iURN, hatm_i);
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
    }

    BigInteger m_i_j;
    BigInteger hatm_i_j;
    String tildem_i_jURN;
    String tildem_i_jPath = "possessionprover.witnesses.randomness.edge.tildem_i_j_";

    for (BaseRepresentation edgeBase : edgeIterator) {
      baseIndex = edgeBase.getBaseIndex();
      tildem_i_jURN = tildem_i_jPath + baseIndex;
      m_i_j = edgeBase.getExponent();
      tildem_i_j = (BigInteger) proverStore.retrieve(tildem_i_jURN);

      hatm_i_j = tildem_i_j.add(this.c.multiply(m_i_j));

      String hatm_i_jURN = "possessionprover.responses.edge.hatm_i_j_" + baseIndex;

      try {
        proverStore.store(hatm_i_jURN, hatm_i_j);
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
    }

    BigInteger hate = tildee.add(this.c.multiply(ePrime));
    /** TODO check if it is tildev or tildevPrime */
    BigInteger hatvPrime = tildev.add(this.c.multiply(vPrime));
    BigInteger hatm_0 = tildem_0.add(this.c.multiply(m_0));

    String hateURN = "possessionprover.responses.hate";
    String hatvPrimeURN = "possessionprover.responses.hatvPrime";
    String hatm_0URN = "possessionprover.responses.hatm_0";

    try {
      proverStore.store(hateURN, hate);
      proverStore.store(hatvPrimeURN, hatvPrime);
      proverStore.store(hatm_0URN, hatm_0);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }

    /** TODO output list of responses */
  }

  private BaseRepresentation checkBaseR_0(BaseIterator baseR0Iterator) {
    BaseRepresentation baseRepR_0;
    if (baseR0Iterator.hasNext()) {
      baseRepR_0 = baseR0Iterator.next();
      if (!baseRepR_0.getBase().equals(baseR_0)) {
        throw new IllegalStateException(
            "base R0 value is not equal to the R0 value of the base iterator");
      }
    } else {
      throw new IllegalStateException("base R0 is not present in base iterator");
    }
    return baseRepR_0;
  }

  //  @Override
  public void computeResponses() {}
}
