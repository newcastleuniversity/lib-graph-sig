package eu.prismacloud.primitives.zkpgs.keys;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Test Signer Key Pair */
@TestInstance(Lifecycle.PER_CLASS)
class SignerKeyPairTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private QRElementPQ baseS;
  private SignerKeyPair signerKeyPair;
  private SignerPublicKey signerPublicKey;
  private SignerPrivateKey signerPrivateKey;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    signerPublicKey = signerKeyPair.getPublicKey();
    signerPrivateKey = signerKeyPair.getPrivateKey();
  }

  @Test
  @DisplayName("Test key generation")
  void keyGen() {
    log.info("@Test: key generation");
    SignerPublicKey pk = signerKeyPair.getPublicKey();

    assertNotNull(signerKeyPair);
    assertNotNull(signerKeyPair.getPrivateKey());
    assertNotNull(signerKeyPair.getPublicKey());
  }

  @Test
  @DisplayName("Test base S")
  void testBaseS() {
    log.info("@Test: baseS");
    baseS = (QRElementPQ) signerPublicKey.getBaseS();
    assertNotNull(baseS);
    QRGroupPQ qrGroup = (QRGroupPQ) signerKeyPair.getQRGroup();

    assertTrue(qrGroup.isElement(baseS.getValue()));
    assertTrue(
        qrGroup.verifySGenerator(
            baseS.getValue(), signerPrivateKey.getpPrime(), signerPrivateKey.getqPrime()));
  }

  @Test
  void getPrivateKey() {
    log.info("@Test: getPrivateKey");
    assertNotNull(signerKeyPair.getPrivateKey());

    assertNotNull(signerKeyPair.getPrivateKey().getpPrime());
    assertTrue(signerKeyPair.getPrivateKey().getpPrime().isProbablePrime(80));

    assertNotNull(signerKeyPair.getPrivateKey().getqPrime());
    assertTrue(signerKeyPair.getPrivateKey().getqPrime().isProbablePrime(80));

    assertNotNull(signerKeyPair.getPrivateKey().getX_r());
    assertNotNull(signerKeyPair.getPrivateKey().getX_r0());
    assertNotNull(signerKeyPair.getPrivateKey().getX_rZ());
  }

  @Test
  void getPublicKey() {
    log.info("@Test: getPublickKey");
    signerPublicKey = signerKeyPair.getPublicKey();
    assertNotNull(signerKeyPair.getPublicKey());
    assertNotNull(signerPublicKey.getModN());
    assertNotNull(signerPublicKey.getBaseS());
    assertNotNull(signerPublicKey.getBaseZ());
    assertNotNull(signerPublicKey.getBaseR_0());
    assertNotNull(signerPublicKey.getBaseR());
  }
}
