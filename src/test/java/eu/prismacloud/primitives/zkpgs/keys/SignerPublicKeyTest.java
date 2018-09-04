package eu.prismacloud.primitives.zkpgs.keys;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class SignerPublicKeyTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private SignerKeyPair signerKeyPair;
  private SignerPublicKey signerPublicKey;
  private QRGroupPQ qrGroup;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    keyGenParameters = baseTest.getKeyGenParameters();
    signerPublicKey = signerKeyPair.getPublicKey();
    qrGroup = (QRGroupPQ) signerPublicKey.getQRGroup();
  }

  @Test
  void getN() {
    BigInteger modN = signerPublicKey.getModN();
    assertNotNull(modN);
  }

  @Test
  void getR_0() {
    GroupElement baseR_0 = signerPublicKey.getBaseR_0();
    assertNotNull(baseR_0);
    assertTrue(qrGroup.isElement(baseR_0.getValue()));
  }

  @Test
  void getR() {
    GroupElement baseR = signerPublicKey.getBaseR();
    assertNotNull(baseR);
    assertTrue(qrGroup.isElement(baseR.getValue()));
  }

  @Test
  void getS() {
    GroupElement baseS = signerPublicKey.getBaseS();
    assertNotNull(baseS);
    assertTrue(
        qrGroup.verifySGenerator(
            baseS.getValue(),
            signerKeyPair.getPrivateKey().getPPrime(),
            signerKeyPair.getPrivateKey().getQPrime()));
    assertTrue(qrGroup.isElement(baseS.getValue()));
  }

  @Test
  void getZ() {
    GroupElement baseZ = signerPublicKey.getBaseZ();
    assertNotNull(baseZ);

    assertTrue(qrGroup.isElement(baseZ.getValue()));
  }
}
