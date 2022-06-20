package uk.ac.ncl.cascade.integration;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.orchestrator.RecipientOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;

import static uk.ac.ncl.cascade.zkpgs.DefaultValues.SERVER;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Testing the signer side of the Issuing protocol with a 2048 modulus bitlength using a persisted
 * and serialised extendedPublicKey to perform computations.
 */
@TestInstance(Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
public class GSRecipientServerTest {
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private RecipientOrchestrator recipientOrchestrator;
	private ExtendedPublicKey extendedPublicKey;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private FilePersistenceUtil persistenceUtil;
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 8888;
	private IMessageGateway messageGateway;

	@BeforeAll
	void setup1Key() throws IOException, ClassNotFoundException, InterruptedException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		persistenceUtil = new FilePersistenceUtil();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();

		Thread.sleep(3000);
		gslog.info("read ExtendedPublicKey...");
		String extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
		extendedPublicKey = (ExtendedPublicKey) persistenceUtil.read(extendedPublicKeyFileName);
		messageGateway = new MessageGatewayProxy(SERVER, HOST, PORT);
	}

//	@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
	@Test
	void test1RecipientSide() throws Exception {

		recipientOrchestrator =
				new RecipientOrchestrator(extendedPublicKey, messageGateway);
		recipientOrchestrator.init();
		recipientOrchestrator.round1();
		recipientOrchestrator.round3();
		recipientOrchestrator.close();
		GSSignature gsSignature = recipientOrchestrator.getGraphSignature();

		// persist graph signature for testing the geo-location separation proof
		gslog.info("persist graph signature");
		GroupElement A = gsSignature.getA();
		persistenceUtil.write(A, "A.ser");
		BigInteger e = gsSignature.getE();
		persistenceUtil.write(e, "e.ser");
		BigInteger v = gsSignature.getV();
		persistenceUtil.write(v, "v.ser");

		// persist encoded base collection to be used in subsequent proofs
		gslog.info("persist encoded base collection");
		BaseCollection baseCollection = recipientOrchestrator.getEncodedBases();
		persistenceUtil.write(baseCollection, "baseCollection.ser");

		assertNotNull(extendedPublicKey);
	}
}
