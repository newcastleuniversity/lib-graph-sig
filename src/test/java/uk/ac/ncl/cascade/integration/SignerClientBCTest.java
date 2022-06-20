package uk.ac.ncl.cascade.integration;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.EnabledOnSuite;
import uk.ac.ncl.cascade.GSSuite;
import uk.ac.ncl.cascade.zkpgs.encoding.PseudonymPrimeEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.PrimeOrderGroup;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SafePrime;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import uk.ac.ncl.cascade.binding.SignerOrchestratorBC;
import uk.ac.ncl.cascade.hashToPrime.HashToPrimeElimination;
import uk.ac.ncl.cascade.hashToPrime.NaorReingoldPRG;
import uk.ac.ncl.cascade.hashToPrime.SquareHashing;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;

import static uk.ac.ncl.cascade.zkpgs.DefaultValues.CLIENT;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
public class SignerClientBCTest {
	private Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private ExtendedKeyPair extendedKeyPair;
	private SignerKeyPair gsk;
	private SignerOrchestratorBC signerOrchestrator;
	private FilePersistenceUtil persistenceUtil;
	private static final String HOST = "127.0.0.1";
	private static final int PORT = 9997;
	private IMessageGateway messageGateway;
	private static final String N_G = "23998E2A7765B6C913C0ED47D9CB3AC03DB4597D1C4438D61C9FD3418F3D78FFADC59E451FE25A28DD91CEDC59E40980BAE8A176EBEECE412F13466862BFFC3077BB9D26FEB8244ACD4B8D8C868E0095E6AC4122B148FE6F398073111DDCAB8194531CFA8D487B70223CF750E653190732F8BA2A2F7D2BFE2ED175A936BBC7671FC0BB9E45276F81A527F06ABBCC0AFFEDC994BF66D9EB69CC7B61F691FFAB1F78BC6E890A92E332E49519056F502F07206E69E6C182B135D785101DCA408E4F484768854CEAFA0C76355F47";
	private BigInteger e_i;
	private SafePrime safePrime;
	private static final int MODULUS_LENGTH = 220;
	private static PrimeOrderGroup group;
	private static final String GROUP_FILENAME = "prime_order_group.ser";
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters hKeyGenParameters;

	@BeforeAll
	void setup2Key() throws IOException, ClassNotFoundException, InterruptedException, EncodingException {
		Thread.sleep(200);
		BaseTest baseTest = new BaseTest();
		baseTest.setup();
		persistenceUtil = new FilePersistenceUtil();
		graphEncodingParameters = baseTest.getGraphEncodingParameters();
		keyGenParameters = baseTest.getKeyGenParameters();
//		Thread.sleep(3000);
		gslog.info("read ExtendedKeyPair..");
		String extendedKeyPairFileName = "ExtendedKeyPair-" + keyGenParameters.getL_n() + ".ser";
		extendedKeyPair = (ExtendedKeyPair) persistenceUtil.read(extendedKeyPairFileName);
		PseudonymPrimeEncoding ps = (PseudonymPrimeEncoding) extendedKeyPair.getGraphEncoding();
		assertTrue(ps instanceof PseudonymPrimeEncoding);
		gslog.info("compute hash to prime...");
		setupHashToPrime();
		this.e_i = computeHashToPrime();
		gslog.info("ei length: " + this.e_i.bitLength());
	}

	void setupHashToPrime() throws IOException, ClassNotFoundException {
		hKeyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);

		File f = new File(GROUP_FILENAME);
		boolean isFile = f.exists();

		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(GROUP_FILENAME);
		} else {
			safePrime = CryptoUtilsFacade.computeRandomSafePrime(hKeyGenParameters);
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
			GroupElement generator = group.createGenerator();
			persistenceUtil.write(group, GROUP_FILENAME);
		}
	}

	private BigInteger computeHashToPrime() {
		BigInteger sqPrime = group.getModulus();
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		NaorReingoldPRG nr = new NaorReingoldPRG(group);
		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, hKeyGenParameters);
		BigInteger message = new BigInteger(N_G, 16);
		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);
		return htp.computePrime(res);
	}

	//	@EnabledOnSuite(name = GSSuite.RECIPIENT_SIGNER)
	@Test
	void test2SignerSide() throws Exception {
//		Thread.sleep(3000);
		IMessageGateway msg = new MessageGatewayProxy(CLIENT, HOST, PORT);
		BigInteger pseudonym = new BigInteger(N_G, 16);
		setupHashToPrime();
		this.e_i = computeHashToPrime();
		gslog.info(" prime number: " + this.e_i);
		signerOrchestrator = new SignerOrchestratorBC(pseudonym, this.e_i, extendedKeyPair, msg);
		signerOrchestrator.init();
		signerOrchestrator.round0();
		signerOrchestrator.round2();
		signerOrchestrator.close();
		assertNotNull(extendedKeyPair);
	}
}
