package eu.prismacloud.primitives.zkpgs.util;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class FilePersistenceUtilTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  // set flag to true to generate a new signer key pair
  private Boolean generateKeyPair = false;
  private FilePersistenceUtil persistenceUtil;
  private KeyGenParameters keyGenParameters;
  private String signerKeyPairFileName;

  @BeforeAll
  void setUp() {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    GraphEncodingParameters graphEncodingParameters = parameters.getGraphEncodingParameters();
    persistenceUtil = new FilePersistenceUtil();
    signerKeyPairFileName = "SignerKeyPair-" + keyGenParameters.getL_n() + ".ser";
  }

  @Test
  void writeSignerKeyPair() throws IOException {

    if (generateKeyPair) {
      log.info("Test writeSignerKeyPair: generating new SignerKeyPair...");

      SignerKeyPair gsk = new SignerKeyPair();
      gsk.keyGen(keyGenParameters);

      persistenceUtil.write(gsk, signerKeyPairFileName);
    }
  }


  @Test
  void readSignerKeyPair() throws IOException, ClassNotFoundException {

    SignerKeyPair signerKeyPair = (SignerKeyPair) persistenceUtil.read(signerKeyPairFileName);

    assertNotNull(signerKeyPair);
    assertNotNull(signerKeyPair.getPrivateKey());
    assertNotNull(signerKeyPair.getPublicKey());
    assertNotNull(signerKeyPair.getQRGroup());
    SignerPublicKey signerPublicKey = signerKeyPair.getPublicKey();
    SignerPrivateKey signerPrivateKey = signerKeyPair.getPrivateKey();

    QRGroupPQ qrGroup = (QRGroupPQ) signerKeyPair.getQRGroup();
    GroupElement baseS = signerPublicKey.getBaseS();

    assertTrue(
        qrGroup.verifySGenerator(
            baseS.getValue(), signerPrivateKey.getpPrime(), signerPrivateKey.getqPrime()));

    assertTrue(qrGroup.isElement(baseS.getValue()));
    assertTrue(qrGroup.isElement(signerPublicKey.getBaseZ().getValue()));
    assertTrue(qrGroup.isElement(signerPublicKey.getBaseR().getValue()));
    assertTrue(qrGroup.isElement(signerPublicKey.getBaseR_0().getValue()));
  }
}
