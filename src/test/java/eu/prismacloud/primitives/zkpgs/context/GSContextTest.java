package eu.prismacloud.primitives.zkpgs.context;

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

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;

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
	void setupKey() throws IOException, ClassNotFoundException {
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
		skp = baseTest.getSignerKeyPair();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
		extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
		extendedKeyPair.generateBases();
		extendedKeyPair.graphEncodingSetup();
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

		for (BigInteger label : labels.values()) {
			ctxList.add(String.valueOf(label));
		}

		graphEncodingParameters.addToChallengeContext(ctxList);

		return ctxList;
	}
	
}
