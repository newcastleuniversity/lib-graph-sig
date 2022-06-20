package uk.ac.ncl.cascade.integration;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.orchestrator.VerifierOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.Vector;
import java.util.logging.Logger;

import static junit.framework.TestCase.assertNotNull;
import static junit.framework.TestCase.assertTrue;

@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
@TestInstance(Lifecycle.PER_CLASS)
public class GSVerifierClientTest {

	private GraphEncodingParameters graphEncodingParameters;
	private KeyGenParameters keyGenParameters;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private ExtendedPublicKey extendedPublicKey;
	private ProofStore<Object> proofStore;
	private VerifierOrchestrator verifierOrchestrator;
	private BaseCollection baseCollection;
	private Iterator<BaseRepresentation> vertexIterator;

	@BeforeAll
	void setupKey() throws InterruptedException, IOException, ClassNotFoundException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();

		gslog.info("read ExtendedPublicKey...");

		String extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
		extendedPublicKey = (ExtendedPublicKey) persistenceUtil.read(extendedPublicKeyFileName);

		String gsSignatureFileName = "graphSignature.ser";
		GSSignature sig = (GSSignature) persistenceUtil.read(gsSignatureFileName);

		gslog.info("read encoded base collection");
		baseCollection = sig.getEncodedBases();
		gslog.info("bases: " + baseCollection.getStringOverview());
	}

//	@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
	@Test
	void testVerifierSide() throws Exception {
//        Thread.sleep(15000); // wait for server socket
		IMessageGateway messageGateway = new MessageGatewayProxy(DefaultValues.CLIENT, "127.0.0.1", 9999);
		verifierOrchestrator = new VerifierOrchestrator(extendedPublicKey, messageGateway);
		Vector<Integer> vertexIndexes = new Vector<>();

		vertexIndexes.add(1);  //GB
		vertexIndexes.add(11); //IT
//		vertexIndexes.add(2);  //GB
//		vertexIndexes.add(17); //IT
//		vertexIndexes.add(23);

		verifierOrchestrator.createQuery(vertexIndexes);
		verifierOrchestrator.init();
		verifierOrchestrator.receiveProverMessage();

		Boolean cLengths = verifierOrchestrator.checkLengths();
		assertTrue(cLengths);
		verifierOrchestrator.executeVerification();
		BigInteger vChallenge = verifierOrchestrator.computeChallenge();
		assertNotNull(vChallenge);

		verifierOrchestrator.verifyChallenge();
		verifierOrchestrator.close();

	}
}
