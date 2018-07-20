package eu.prismacloud.primitives.zkpgs.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
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
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Testing the signer side of the Issuing protocol with a 2048 modulus bitlength using a persisted
 * and serialised extendedPublicKey to perform computations.
 */
@TestInstance(Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
public class GSRecipientServerTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ExtendedKeyPair extendedKeyPair;
  private SignerKeyPair signerKeyPair;
  private RecipientOrchestrator recipientOrchestrator;
  private ExtendedPublicKey extendedPublicKey;

  @BeforeAll
  void setup1Key() throws IOException, ClassNotFoundException {
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
  
  @EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
  @Test
  void test1RecipientSide() throws Exception {

    recipientOrchestrator =
        new RecipientOrchestrator(extendedPublicKey, keyGenParameters, graphEncodingParameters);

    recipientOrchestrator.round1();

    recipientOrchestrator.round3();

    recipientOrchestrator.close();

    assertNotNull(extendedPublicKey);
  }
}
