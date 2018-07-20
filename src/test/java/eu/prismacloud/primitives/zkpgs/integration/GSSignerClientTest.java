package eu.prismacloud.primitives.zkpgs.integration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.orchestrator.SignerOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.condition.DisabledIf;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Testing the recipient side of the Issuing protocol with a 2048 modulus bitlength using a persisted
 * and serialised SignerKeyPair to perform computations.
 */
@TestInstance(Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
public class GSSignerClientTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ExtendedKeyPair extendedKeyPair;
  private SignerKeyPair gsk;
  private SignerOrchestrator signerOrchestrator;
  
  @BeforeAll
  void setup2Key() throws IOException, ClassNotFoundException, InterruptedException {
    Thread.sleep(200);
    
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
  }
  
  @EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
  @Test
  void test2SignerSide() throws Exception {
    signerOrchestrator =
        new SignerOrchestrator(extendedKeyPair, keyGenParameters, graphEncodingParameters);

    signerOrchestrator.round0();

    signerOrchestrator.round2();

    signerOrchestrator.close();

    assertNotNull(extendedKeyPair);
  }
}
