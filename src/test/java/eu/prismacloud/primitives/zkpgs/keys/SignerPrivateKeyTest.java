package eu.prismacloud.primitives.zkpgs.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.orchestrator.RecipientOrchestrator;
import eu.prismacloud.primitives.zkpgs.orchestrator.SignerOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class SignerPrivateKeyTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private SignerKeyPair signerKeyPair;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private ProofSignature proofSignature;
  private SignerOrchestrator signerOrchestrator;
  private RecipientOrchestrator recipientOrchestrator;
  private GroupElement baseR0;
  private SignerPublicKey publicKey;
  private SignerPrivateKey privateKey;
  private QRGroupPQ qrGroup;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    privateKey = signerKeyPair.getPrivateKey();
    qrGroup = (QRGroupPQ) publicKey.getQRGroup();
  }

  @Test
  void getpPrime() {
    BigInteger pPrime = privateKey.getpPrime();
    assertNotNull(pPrime);
    assertEquals(keyGenParameters.getL_n() / 2, pPrime.bitLength() + 1);
    BigInteger p = qrGroup.getP();
    BigInteger pPrimeTest = p.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue());

    assertEquals(pPrimeTest, pPrime);
  }

  @Test
  void getqPrime() {
    BigInteger qPrime = privateKey.getqPrime();

    assertNotNull(qPrime);
    assertEquals(keyGenParameters.getL_n() / 2, qPrime.bitLength() + 1);

    BigInteger q = qrGroup.getQ();
    BigInteger qPrimeTest = q.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue());

    assertEquals(qPrimeTest, qPrime);
  }

  @Test
  void getX_r() {
    BigInteger x_r = privateKey.getX_r();
    assertNotNull(x_r);

  }

  @Test
  void getX_r0() {
    BigInteger x_r0 = privateKey.getX_r0();
    assertNotNull(x_r0);
  }

  @Test
  void getX_rZ() {
    BigInteger x_rZ = privateKey.getX_rZ();
    assertNotNull(x_rZ);
  }
}
