package uk.ac.ncl.cascade.integration;

import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.*;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigningOracle;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import uk.ac.ncl.cascade.binding.ProverOrchestratorBC;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.logging.Logger;

import static uk.ac.ncl.cascade.zkpgs.DefaultValues.SERVER;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testing the prover side of the geo-location separation proof
 */
@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
@TestInstance(Lifecycle.PER_CLASS)
public class ProverServerBCTest {
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private ProverOrchestratorBC proverOrchestrator;
	private ExtendedPublicKey extendedPublicKey;
	private FilePersistenceUtil persistenceUtil;
	private GroupElement A;
	private BigInteger e;
	private BigInteger v;
	private BaseCollection baseCollection;
	private SignerPublicKey publicKey;
	private SignerKeyPair signerKeyPair;
	private SignerPrivateKey privateKey;
	private GSSignature gsSignature;
	private BigInteger m_0;
	private GSCommitment commitment;
	private Iterator<BaseRepresentation> vertexIterator;
	private ProofStore<Object> proofStore;
	private GSSigningOracle oracle;
	private GSSignature sigmaM;
	private GSSignature sig;
	private String gsSignatureFileName;
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 9999;

	@BeforeAll
	void setupKey()
			throws IOException, ClassNotFoundException, InterruptedException, ProofStoreException {
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
		gslog.info("read persisted graph signature");

		gsSignatureFileName = "vcSignature.ser";
//		gsSignatureFileName = "signer-infra.gs.ser";
		sig = (GSSignature) persistenceUtil.read(gsSignatureFileName);

		gslog.info("read encoded base collection");
		baseCollection = sig.getEncodedBases();
//        gslog.info("bases: " + baseCollection.getStringOverview());

		proofStore = new ProofStore<>();
	}

	//	@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
	@Test
	void testProverSide() throws Exception {
		IMessageGateway msg = new MessageGatewayProxy(SERVER, HOST, PORT);
		proverOrchestrator = new ProverOrchestratorBC(extendedPublicKey, msg);
		proverOrchestrator.readSignature(gsSignatureFileName);
		proverOrchestrator.init();
		proverOrchestrator.executePreChallengePhase();
		BigInteger cChallenge = proverOrchestrator.computeChallenge();
		assertNotNull(cChallenge);
		proverOrchestrator.executePostChallengePhase(cChallenge);
		proverOrchestrator.close();
	}

}
