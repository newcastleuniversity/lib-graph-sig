package uk.ac.ncl.cascade.integration;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SignerOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Testing the recipient side of the Issuing protocol with a 2048 modulus bitlength using a
 * persisted and serialised SignerKeyPair to perform computations.
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
	private FilePersistenceUtil persistenceUtil;
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 8888;
	private IMessageGateway messageGateway;

	@BeforeAll
	void setup2Key() throws IOException, ClassNotFoundException, InterruptedException, EncodingException {
		Thread.sleep(200);
		persistenceUtil = new FilePersistenceUtil();
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		gsk = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		messageGateway = new MessageGatewayProxy(DefaultValues.CLIENT, HOST, PORT);
	}

//	@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
	@Test
	void test2SignerSide() throws Exception {
		Thread.sleep(3000);
		signerOrchestrator = new SignerOrchestrator(extendedKeyPair, messageGateway);
		signerOrchestrator.init();
		signerOrchestrator.round0();

		signerOrchestrator.round2();

		signerOrchestrator.close();

		assertNotNull(extendedKeyPair);
	}
}
