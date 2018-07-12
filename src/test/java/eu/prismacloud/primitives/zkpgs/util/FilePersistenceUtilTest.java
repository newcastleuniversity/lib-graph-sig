package eu.prismacloud.primitives.zkpgs.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FilePersistenceUtilTest {
  private static final String SIGNER_KEYPAIR_FILE = "SingerKeyPair.ser";
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private FilePersistenceUtil persistenceUtil;
  private KeyGenParameters keyGenParameters;

  @BeforeEach
  void setUp() {

    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    GraphEncodingParameters graphEncodingParameters = parameters.getGraphEncodingParameters();
    persistenceUtil = new FilePersistenceUtil();
  }

  @Test
  void writeSignerKeyPair() throws IOException {
    assumeTrue(BaseTest.EXECUTE_INTENSIVE_TESTS);

    SignerKeyPair gsk = new SignerKeyPair();
    gsk.keyGen(keyGenParameters);

    persistenceUtil.write(gsk, "SignerKeyPair-" + keyGenParameters.getL_n() + ".ser");
  }

  @Test
  void readSignerKeyPair() throws IOException, ClassNotFoundException {

    SignerKeyPair signerKeyPair =
        (SignerKeyPair) persistenceUtil.read("SignerKeyPair-" + keyGenParameters.getL_n() + ".ser");

    assertNotNull(signerKeyPair);
    assertNotNull(signerKeyPair.getPrivateKey());
    assertNotNull(signerKeyPair.getPublicKey());
    assertNotNull(signerKeyPair.getQRGroup());
    SignerPublicKey signerPublicKey = signerKeyPair.getPublicKey();
    SignerPrivateKey signerPrivateKey = signerKeyPair.getPrivateKey();

    assertEquals(keyGenParameters.getL_n(), signerPublicKey.getModN().bitLength() + 1);

    QRGroupPQ qrGroup = (QRGroupPQ) signerKeyPair.getQRGroup();

    assertTrue(qrGroup.isElement(signerPublicKey.getBaseS().getValue()));
    assertTrue(qrGroup.isElement(signerPublicKey.getBaseZ().getValue()));
    assertTrue(qrGroup.isElement(signerPublicKey.getBaseR().getValue()));
    assertTrue(qrGroup.isElement(signerPublicKey.getBaseR_0().getValue()));

    GroupElement baseS = signerPublicKey.getBaseS();

    assertTrue(qrGroup.verifySGenerator(
        baseS.getValue(),
        signerPrivateKey.getpPrime(),
        signerPrivateKey.getqPrime()));
  }
}
