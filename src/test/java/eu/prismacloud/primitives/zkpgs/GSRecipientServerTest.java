package eu.prismacloud.primitives.zkpgs;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.orchestrator.RecipientOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/**
 * Testing the signer side of the Issuing protocol with a 2048 modulus bitlength using a persisted
 * and serialised extendedPublicKey to perform computations.
 */
@TestInstance(Lifecycle.PER_CLASS)
public class GSRecipientServerTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ExtendedKeyPair extendedKeyPair;
  private SignerKeyPair signerKeyPair;
  private RecipientOrchestrator recipientOrchestrator;
  private ExtendedPublicKey extendedPublicKey;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();

    extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    
    extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
    extendedKeyPair = null;
    signerKeyPair = null;
  }

  @Test
  void testRecipientSide() throws Exception {

    recipientOrchestrator =
        new RecipientOrchestrator(
            extendedPublicKey, keyGenParameters, graphEncodingParameters);

    recipientOrchestrator.round1();

    recipientOrchestrator.round3();

    assertNotNull(extendedKeyPair);
  }
}
