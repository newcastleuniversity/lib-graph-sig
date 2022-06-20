package uk.ac.ncl.cascade.context;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

@TestInstance(Lifecycle.PER_CLASS)
class GSContextTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	
	private SignerKeyPair skp;
	private ExtendedKeyPair extendedKeyPair;
	private ExtendedPublicKey epk;
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private GSContext context;

	@BeforeAll
	void setupKey() throws IOException, ClassNotFoundException, EncodingException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		skp = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.setupEncoding();
		extendedKeyPair.createExtendedKeyPair();
		
		epk = extendedKeyPair.getExtendedPublicKey();
	}
	
	@BeforeEach
	void setUp() throws Exception {
		context = new GSContext(epk);
	}
	
	@Test
	void testComputeChallengeContext() {
		List<String> ctxList = context.computeChallengeContext();
		
		List<String> expectedList = computeChallengeContext();
		
		assertEquals(expectedList, ctxList);
	}

	/**
	 * Creates a context list as comparison.
	 * 
	 * @return challenge context list.
	 */
	public List<String> computeChallengeContext() {
		List<String> ctxList = new ArrayList<String>();

		SignerPublicKey publicKey = epk.getPublicKey();
		Map<URN, BaseRepresentation> bases = epk.getBases();
		Map<URN, BigInteger> labels = epk.getLabelRepresentatives();

		keyGenParameters.addToChallengeContext(ctxList);

		publicKey.addToChallengeContext(ctxList);

		for (BaseRepresentation baseRepresentation : bases.values()) {
			baseRepresentation.addToChallengeContext(ctxList);
		}
		
		// Intentionally removed labels from context, not specified as such.
//		for (BigInteger label : labels.values()) {
//			ctxList.add(String.valueOf(label));
//		}

		graphEncodingParameters.addToChallengeContext(ctxList);

		return ctxList;
	}
	
}
