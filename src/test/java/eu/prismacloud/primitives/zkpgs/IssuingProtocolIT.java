package eu.prismacloud.primitives.zkpgs;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.verifier.GroupSetupVerifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Testing Issuing protocol with a 2048 modulus bitlength using a persisted and serialised
 * SignerKeyPair to perform computations.
 */
public class IssuingProtocolIT {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ExtendedKeyPair extendedKeyPair;
  private SignerKeyPair gsk;
  private GroupSetupProver groupSetupProver;
  private ProofStore<Object> proofStore;

  @BeforeEach
  void setUp()
      throws NoSuchAlgorithmException, ProofStoreException, IOException, ClassNotFoundException {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
  }

  @ParameterizedTest(name = "{index} => message=''{0}''")
  @ValueSource(strings = {"2048"})
  void shouldCreateASignerKeyPair(String bitLength) throws IOException, ClassNotFoundException {

    if (bitLength.equals("2048")) {
      FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
      gsk = (SignerKeyPair) persistenceUtil.read("SignerKeyPair-2048.ser");
    } else {
      gsk.keyGen(keyGenParameters);
    }

    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }

  @Test
  void testExtendedKeyPair() throws IOException, ClassNotFoundException {
    shouldCreateASignerKeyPair("2048");

    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
  }



  @Test
  void testIssuing() {
    /** TODO finish testing the Issuing Protocol */

    assertNotNull(extendedKeyPair);
  }
}
