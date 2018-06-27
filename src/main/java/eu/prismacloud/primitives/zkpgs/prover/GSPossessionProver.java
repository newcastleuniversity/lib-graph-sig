package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GSPossessionProver { //implements IProver, Storable {

  private GSSignature blindedSignature;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger R_0;
  private BigInteger tildem_0;
  private BigInteger tildevPrime;
  private GraphRepresentation graphRepresentation;
  private ProofStore<Object> proverStore;
  private KeyGenParameters keyGenParameters;
  private Map<URN, BaseRepresentation> bases;
  private Map<URN, BaseRepresentation> edges;
  private BigInteger tildeZ;
  private BigInteger tildee;
  private Map<URN, BigInteger> vertexWitnesses;
  private Map<URN, BigInteger> edgeWitnesses;
  private BigInteger tildem_i;
  private BigInteger tildem_i_j;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private BigInteger c;
  private int baseIndex;

  public GSPossessionProver(
      GSSignature blindedSignature,
      ExtendedPublicKey extendedPublicKey,
      BigInteger R_0,
      BigInteger tildem_0,
      BigInteger tildevPrime,
      GraphRepresentation graphRepresentation,
      ProofStore<Object> proverStore,
      KeyGenParameters keyGenParameters) {

    this.blindedSignature = blindedSignature;
    this.extendedPublicKey = extendedPublicKey;
    this.R_0 = R_0;
    this.tildem_0 = tildem_0;
    this.tildevPrime = tildevPrime;
    this.graphRepresentation = graphRepresentation;
    this.proverStore = proverStore;
    //    this.vertexBase = graphRepresentation.
    this.keyGenParameters = keyGenParameters;
  }

  public GSPossessionProver() {}

  public BigInteger getTildeZ() {
    return this.tildeZ;
  }

//  @Override
  public void createWitnessRandomness() {

    int tildeeLength =
        keyGenParameters.getL_prime_e()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_H()
            + 1;
    tildee = CryptoUtilsFacade.computeRandomNumber(tildeeLength);

    int tildevLength =
        keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
    BigInteger tildev = CryptoUtilsFacade.computeRandomNumber(tildevLength);

    int messageLength =
        keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
    BigInteger tildem_0 = CryptoUtilsFacade.computeRandomNumber(messageLength);

    bases = GraphRepresentation.getEncodedBases();

    vertexWitnesses = new LinkedHashMap<>();
    edgeWitnesses = new LinkedHashMap<>();

    for (BaseRepresentation base : bases.values()) {
      if (base.getBaseType() == BASE.VERTEX) {
        tildem_i = CryptoUtilsFacade.computeRandomNumber(messageLength);

        vertexWitnesses.put(
            URN.createZkpgsURN(
                "possessionprover.witnesses.randomness.vertex.tildem_" + base.getBaseIndex()),
            tildem_i);
      } else if (base.getBaseType() == BASE.EDGE) {
        tildem_i_j = CryptoUtilsFacade.computeRandomNumber(messageLength);
        edgeWitnesses.put(
            URN.createZkpgsURN(
                "possessionprover.witnesses.randomness.edge.tildem_i_j_" + base.getBaseIndex()),
            tildem_i_j);
      }
    }

    try {
      storeWitnessRandomness(tildem_i, tildem_i_j, tildev, tildem_0);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  private void storeWitnessRandomness(
      BigInteger tildem_i, BigInteger tildem_i_j, BigInteger tildev, BigInteger tildem_0)
      throws Exception {
    String tildeeURN = "possessionprover.witnesses.randomness.tildee";
    proverStore.store(tildeeURN, tildee);

    String tildevURN = "possessionprover.witnesses.randomness.tildev";
    proverStore.store(tildevURN, tildev);

    String tildem_0URN = "possessionprover.witnesses.randomness.tildem_0";
    proverStore.store(tildem_0URN, tildem_0);

    String tildem_iURN = "possessionprover.witnesses.randomness.tildem_i";
    proverStore.store(tildem_iURN, vertexWitnesses);

    String tildem_i_jURN = "possessionprover.witnesses.randomness.tildem_i_j";
    proverStore.store(tildem_i_jURN, edgeWitnesses);
  }

  public Map<URN, BigInteger> getVertexWitnesses() {
    return this.vertexWitnesses;
  }

  public Map<URN, BigInteger> getEdgeWitnesses() {
    return this.edgeWitnesses;
  }

  private Map<URN, BigInteger> populateExponents(BigInteger tildee, BigInteger tildem_0) {
    Map<URN, BigInteger> exponents = new LinkedHashMap<URN, BigInteger>();

    exponents.put(URN.createZkpgsURN("message.tildee"), tildee);
    exponents.put(URN.createZkpgsURN("message.tildem_0"), tildem_0);

    for (BaseRepresentation base : bases.values()) {

      if (base.getBaseType() == BASE.VERTEX) {

        exponents.put(URN.createZkpgsURN("message.m_i_" + base.getBaseIndex()), base.getExponent());
      } else if (base.getBaseType() == BASE.EDGE) {

        exponents.put(
            URN.createZkpgsURN("message.m_i_j_" + base.getBaseIndex()), base.getExponent());
      }
    }

    //    for (BaseRepresentation edge : edges.values()) {
    //      exponents.add(edge.getExponents());
    //    }
    exponents.put(URN.createZkpgsURN("message.tildevPrime"), tildevPrime);
    return exponents;
  }

  private Map<URN, GroupElement> populateBases() {
    Map<URN, GroupElement> bases = new LinkedHashMap<URN, GroupElement>();
    /** TODO fix populating bases */
    //    bases.put(URN.createZkpgsURN("blindedSignature.A"), blindedSignature.getA());
    //    bases.put(URN.createZkpgsURN("base.R_0"), R_0);

    for (BaseRepresentation base : this.bases.values()) {
      if (base.getBaseType() == BASE.VERTEX) {

        bases.put(URN.createZkpgsURN("bases.R_i_" + base.getBaseIndex()), base.getBase());
      } else if (base.getBaseType() == BASE.EDGE) {

        bases.put(URN.createZkpgsURN("bases.R_i_j_" + base.getBaseIndex()), base.getBase());
      }
    }
    bases.put(URN.createZkpgsURN("base.S"), extendedPublicKey.getPublicKey().getBaseS());
    return bases;
  }

//  @Override
  public void computeWitness() {

    Map<URN, GroupElement> bases = populateBases();

    Map<URN, BigInteger> exponents = populateExponents(tildee, tildem_0);

    tildeZ =
        CryptoUtilsFacade.computeMultiBaseEx(
            bases, exponents, extendedPublicKey.getPublicKey().getModN());
  }

//  @Override
//  public BigInteger computeChallenge() {}

  public void setChallenge(BigInteger challenge) {
    this.c = challenge;
  }

//  @Override
  public void computeResponses() {
    /** TODO retrieve witnesses from the proofstore */
    String ePrimeURN = "prover.blindedgs.ePrime";
    BigInteger ePrime = (BigInteger) proverStore.retrieve(ePrimeURN);

    String vPrimeURN = "prover.blindedgs.vPrime";
    BigInteger vPrime = (BigInteger) proverStore.retrieve(vPrimeURN);

    /** TODO fix m_0 */
    String m_0URN = "prover.m_0";
    BigInteger m_0 = (BigInteger) proverStore.retrieve(m_0URN);

    /** TODO retrieve m_i, m_ij */
    String vertexBasesURN = "bases.vertex.R_i";
    Map<URN, BaseRepresentation> vertexBases =
        (Map<URN, BaseRepresentation>) proverStore.retrieve(vertexBasesURN);

    String edgeBasesURN = "bases.edge.R_i_j";
    Map<URN, BaseRepresentation> edgeBases =
        (Map<URN, BaseRepresentation>) proverStore.retrieve(edgeBasesURN);

    String tildem_iMapURN = "possessionprover.witnesses.randomness.tildem_i";
    Map<URN, BaseRepresentation> tildem_iMap =
        (Map<URN, BaseRepresentation>) proverStore.retrieve(tildem_iMapURN);

    BigInteger m_i;
    BigInteger hatm_i;
    for (BaseRepresentation vertexBase : vertexBases.values()) {
      baseIndex = vertexBase.getBaseIndex();
      URN tildem_iURN =
          URN.createURN(
              URN.getZkpgsNameSpaceIdentifier(),
              "possessionprover.witnesses.randomness.tildem_" + vertexBase.getBaseIndex());
      m_i = vertexBase.getExponent();
      tildem_i = tildem_iMap.get(tildem_iURN).getExponent();
      hatm_i = tildem_i.add(this.c.multiply(m_i));

      String hatm_iURN = "possessionprover.responses.hatm_" + baseIndex;

      try {
        proverStore.store(hatm_iURN, hatm_i);
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
    }

    BigInteger m_i_j;
    BigInteger hatm_i_j;

    for (BaseRepresentation edgeBase : edgeBases.values()) {
      baseIndex = edgeBase.getBaseIndex();
      URN tildem_i_jURN =
          URN.createURN(
              URN.getZkpgsNameSpaceIdentifier(),
              "possessionprover.witnesses.randomness.tildem_i_j_" + edgeBase.getBaseIndex());
      m_i_j = edgeBase.getExponent();
      tildem_i_j = tildem_iMap.get(tildem_i_jURN).getExponent();
      hatm_i_j = tildem_i_j.add(this.c.multiply(m_i_j));

      String hatm_i_jURN = "possessionprover.responses.hatm_i_j_" + baseIndex;

      try {
        proverStore.store(hatm_i_jURN, hatm_i_j);
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
    }

    BigInteger hate = tildee.add(this.c.multiply(ePrime));
    BigInteger hatvPrime = tildevPrime.add(this.c.multiply(vPrime));
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

}
