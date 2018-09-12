package eu.prismacloud.primitives.zkpgs.integration;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.VerifierOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
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

		String gsSignatureFileName = "signer-infra.gs.ser";
		GSSignature sig = (GSSignature) persistenceUtil.read(gsSignatureFileName);

		gslog.info("read encoded base collection");
		baseCollection = sig.getEncodedBases();
		gslog.info("bases: " + baseCollection.getStringOverview());
	}

	@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
	@Test
	void testVerifierSide() throws Exception {
//        Thread.sleep(15000); // wait for server socket

		verifierOrchestrator = new VerifierOrchestrator(extendedPublicKey);
		Vector<Integer> vertexIndexes = new Vector<>();

		vertexIndexes.add(1);  //GB
		vertexIndexes.add(16); //IT
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
