package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
@TestInstance(Lifecycle.PER_CLASS)
class GSProverTest {

  private SignerKeyPair signerKeyPair;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private GSProver prover;
  private BigInteger testMessage;
  private ExtendedPublicKey extendedPublicKey;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private BaseCollection baseCollection;
  private BigInteger v;
  private BigInteger e;
  private GroupElement A;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException, InterruptedException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    Thread.sleep(3000);

    gslog.info("reading extended public key");
    String extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
    extendedPublicKey = (ExtendedPublicKey) persistenceUtil.read(extendedPublicKeyFileName);

    proofStore = new ProofStore<Object>();
    prover = new GSProver(proofStore, extendedPublicKey, keyGenParameters);

    gslog.info("read persisted graph signature");
    A = (GroupElement) persistenceUtil.read("A.ser");
    e = (BigInteger) persistenceUtil.read("e.ser");
    v = (BigInteger) persistenceUtil.read("v.ser");

    gslog.info("read encoded base collection");
    baseCollection = (BaseCollection) persistenceUtil.read("baseCollection.ser");
  }

  @Test
  @EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
  void getCommitmentMap() throws Exception {
    BaseRepresentation baseRepresentation =
        new BaseRepresentation(extendedPublicKey.getPublicKey().getBaseR_0(), 0, BASE.VERTEX);
    testMessage = CryptoUtilsFacade.generateRandomPrime(keyGenParameters.getL_m());
    baseRepresentation.setExponent(testMessage);
    Map<URN, BaseRepresentation> baseRepresentationMap = new HashMap<>();
    baseRepresentationMap.put(URN.createZkpgsURN("base.test"), baseRepresentation);

    prover.computeCommitments(baseCollection.createIterator(BASE.VERTEX));
    Map<URN, GSCommitment> cMap = prover.getCommitmentMap();

    assertNotNull(cMap);
    assertEquals(1, cMap.size());
  }

  @Test
  void computeCommitments() throws Exception {
    BaseRepresentation baseRepresentation =
        new BaseRepresentation(extendedPublicKey.getPublicKey().getBaseR_0(), 0, BASE.VERTEX);
    testMessage = CryptoUtilsFacade.generateRandomPrime(keyGenParameters.getL_m());
    baseRepresentation.setExponent(testMessage);
    Map<URN, BaseRepresentation> baseRepresentationMap = new HashMap<>();
    baseRepresentationMap.put(URN.createZkpgsURN("base.test"), baseRepresentation);

    prover.computeCommitments(baseCollection.createIterator(BASE.VERTEX));
    Map<URN, GSCommitment> cMap = prover.getCommitmentMap();
    assertNotNull(cMap);
    assertEquals(1, cMap.size());
    String commitmentURN = "prover.commitments.C_0";
    GSCommitment gsCommitment = cMap.get(URN.createZkpgsURN(commitmentURN));
  }

  @Test
  void computeBlindedSignature() {
	  fail("Test not implemented yet.");
  }

  @Test
  void sendMessage() {
	  fail("Test not implemented yet.");
  }
}
