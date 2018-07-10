package eu.prismacloud.primitives.zkpgs.orchestrator;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.GroupSetupVerifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class SignerOrchestratorTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private SignerKeyPair gsk;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private ProofSignature proofSignature;
  private SignerOrchestrator signerOrchestrator;
  private RecipientOrchestrator recipientOrchestrator;
  private GroupElement baseR0;
  private String bitLength = "2048";
  private SignerPublicKey publicKey;
  private SignerPrivateKey privateKey;

  @BeforeEach
  void setUp()
      throws NoSuchAlgorithmException, ProofStoreException, IOException, ClassNotFoundException {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();

    SignerKeyPair gsk = new SignerKeyPair();

    if (bitLength.equals("2048")) {
      FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
      gsk = (SignerKeyPair) persistenceUtil.read("SignerKeyPair-" + bitLength + ".ser");
    } else {
      gsk.keyGen(keyGenParameters);
    }

    privateKey = gsk.getPrivateKey();
    publicKey = gsk.getPublicKey();

    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());

    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
  }

  @Test
  void testCreateSignerOrchestrator() {
    signerOrchestrator =
        new SignerOrchestrator(extendedKeyPair, keyGenParameters, graphEncodingParameters);

    recipientOrchestrator =
        new RecipientOrchestrator(
            extendedKeyPair.getExtendedPublicKey(), keyGenParameters, graphEncodingParameters);

    assertNotNull(signerOrchestrator);
    assertNotNull(recipientOrchestrator);
  }


  @Test
  void round0() throws Exception {
    signerOrchestrator.round0();

    recipientOrchestrator.round1();

    signerOrchestrator.round2();

    recipientOrchestrator.round3();

    //    recipientOrchestrator.round3();

  }

  @Test
  void round2() {}

  @Test
  void computeChallenge() {}

  @Test
  void verifyChallenge() {}

  @Test
  void createPartialSignature() {}

  @Test
  void computeRandomness() {}

  @Test
  void computevPrimePrime() {}

  @Test
  void store() {}
}
