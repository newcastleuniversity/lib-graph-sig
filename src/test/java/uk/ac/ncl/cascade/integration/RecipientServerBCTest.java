package uk.ac.ncl.cascade.integration;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.*;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import uk.ac.ncl.cascade.binding.RecipientOrchestratorBC;

import java.io.IOException;
import java.util.logging.Logger;

import static uk.ac.ncl.cascade.zkpgs.DefaultValues.SERVER;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
public class RecipientServerBCTest {
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private RecipientOrchestratorBC recipientOrchestrator;
	private ExtendedPublicKey extendedPublicKey;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private FilePersistenceUtil persistenceUtil;
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 9997;
	private IMessageGateway messageGateway;
	private SignerKeyPair signerKeyPair;
	private SignerPrivateKey privateKey;
	private SignerPublicKey publicKey;

	@BeforeAll
	void setup1Key() throws IOException, ClassNotFoundException, InterruptedException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		persistenceUtil = new FilePersistenceUtil();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();

//		Thread.sleep(3000);
		gslog.info("read ExtendedKeyPair..");
		String extendedKeyPairFileName = "ExtendedKeyPair-" + keyGenParameters.getL_n() + ".ser";
		ExtendedKeyPair extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		PseudonymPrimeEncoding ps = (PseudonymPrimeEncoding) extendedKeyPair.getGraphEncoding();
		assertTrue(ps instanceof PseudonymPrimeEncoding);
		extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
	}

	//	@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
	@Test
	void test1RecipientSide() throws Exception {
		IMessageGateway msg = new MessageGatewayProxy(SERVER, HOST, PORT);
		recipientOrchestrator = new RecipientOrchestratorBC(extendedPublicKey, msg);
		recipientOrchestrator.init();
		recipientOrchestrator.round1();
		recipientOrchestrator.round3();
		recipientOrchestrator.close();
		GSSignature gsSignature = recipientOrchestrator.getSignature();
		assertNotNull(gsSignature);
		persistenceUtil.write(gsSignature, "vcSignature.ser");
	}
}

