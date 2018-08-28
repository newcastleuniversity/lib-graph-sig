package eu.prismacloud.primitives.zkpgs.orchestrator;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GroupSetupVerifierOrchestratorTest {
  private SignerKeyPair gsk;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private GroupSetupProverOrchestrator gsProverOrchestrator;
  private ExtendedPublicKey extendedPublicKey;
  private GroupSetupVerifierOrchestrator gsVerifierOrchestrator;
  private ProofSignature proofSignature;
  private SignerPublicKey signerPublicKey;
  private BaseCollection baseCollection;
  private BigInteger cChallenge;
  private BigInteger hatC;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
    signerPublicKey = extendedPublicKey.getPublicKey();
    proofStore = new ProofStore<Object>();
    baseCollection = extendedPublicKey.getBaseCollection();
    proofSignature = createTestProofSignature();
    gsVerifierOrchestrator =
        new GroupSetupVerifierOrchestrator(proofSignature, extendedPublicKey, proofStore);
  }

  @Test
  void init() {}

  @Test
  void executeVerification() {
    boolean isVerified = gsVerifierOrchestrator.executeVerification(cChallenge);
    assertTrue(isVerified);
  }

  @Test
  void computeChallenge() throws ProofStoreException {
    hatC = gsVerifierOrchestrator.computeChallenge();
    assertNotNull(hatC);
  }

  @Test
  void checkLengths() {
    boolean isLengthCorrect = gsVerifierOrchestrator.checkLengths();
    assertNotNull(isLengthCorrect);
    assertTrue(isLengthCorrect);
  }

  @Test
  void testIllegalLengths() {
    fail("Test illegal lengths for the GroupSetupVerifierOrchesttrator");
  }

  private ProofSignature createTestProofSignature() {
    Map<URN, Object> proofSignatureElements = new HashMap<>();

    proofSignatureElements.put(
        URN.createZkpgsURN("proofsignature.P.modN"), signerPublicKey.getModN());
    proofSignatureElements.put(
        URN.createZkpgsURN("proofsignature.P.baseS"), signerPublicKey.getBaseS());
    proofSignatureElements.put(
        URN.createZkpgsURN("proofsignature.P.baseZ"), signerPublicKey.getBaseZ());
    proofSignatureElements.put(
        URN.createZkpgsURN("proofsignature.P.baseR"), signerPublicKey.getBaseR());
    proofSignatureElements.put(
        URN.createZkpgsURN("proofsignature.P.baseR_0"), signerPublicKey.getBaseR_0());
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

    /** TODO add values in test proof signature */
    //        proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_Z"),
    // this.hatr_Z);
    //        proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr"), this.hatr);
    //        proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_0"),
    // this.hatr_0);
    //        proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i"),
    // this.vertexResponses);
    //    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.hatr_i_j"),
    // this.edgeResponses);
    cChallenge = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P.c"), cChallenge);

    return new ProofSignature(proofSignatureElements);
  }
}
