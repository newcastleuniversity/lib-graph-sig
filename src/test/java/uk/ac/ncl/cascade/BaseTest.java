package uk.ac.ncl.cascade;

import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.JSONParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Base test class for using persisted SignerKeyPair
 */
@TestInstance(Lifecycle.PER_CLASS)
public class BaseTest {
	/**
	 * flag to execute performance intensive tests
	 */
	public static final Boolean EXECUTE_INTENSIVE_TESTS = false;
	public static final String MODULUS_BIT_LENGTH = "2048";

	private KeyGenParameters keyGenParameters;
	private SignerKeyPair gsk;

	public KeyGenParameters getKeyGenParameters() {
		return this.keyGenParameters;
	}

	public GraphEncodingParameters getGraphEncodingParameters() {
		return this.graphEncodingParameters;
	}

	private GraphEncodingParameters graphEncodingParameters;

	@BeforeAll
	public void setup() {
		JSONParameters parameters = new JSONParameters();
		keyGenParameters = parameters.getKeyGenParameters();
		graphEncodingParameters = parameters.getGraphEncodingParameters();
	}

	@ParameterizedTest(name = "{index} => bitLength=''{0}''")
	@ValueSource(strings = {"2048"})
	public void shouldCreateASignerKeyPair(String bitLength)
			throws IOException, ClassNotFoundException {
		String signerKeyPair = "SignerKeyPair-" + bitLength + ".ser";
		File keypairFile = new File(signerKeyPair);
		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
		if (bitLength.equals("2048") && keypairFile.exists()) {
			gsk = (SignerKeyPair) persistenceUtil.read("SignerKeyPair-" + bitLength + ".ser");
		} else {
			gsk = new SignerKeyPair();
			gsk.keyGen(keyGenParameters);
			persistenceUtil.write(gsk, signerKeyPair);
		}

		assertNotNull(gsk);
		assertNotNull(gsk.getPrivateKey());
		assertNotNull(gsk.getPublicKey());
	}

	public SignerKeyPair getSignerKeyPair() {
		return gsk;
	}
}
