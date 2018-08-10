package eu.prismacloud.primitives.zkpgs.verifier;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
class GSVerifierTest {

  private SignerKeyPair signerKeyPair;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private GSVerifier verifier;
  private ExtendedPublicKey extendedPublicKey;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
    extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
    proofStore = new ProofStore<Object>();
    verifier = new GSVerifier(extendedPublicKey, keyGenParameters);
  }

//  @Test
//  void getBarV() {
//    Map<URN, BigInteger> barV = verifier.getBarV();
//    assertNotNull(barV);
//  }
//
//  @Test
//  void checkLengths() {
//    verifier.checkLengths(new ProofSignature(new HashMap<>()));
//  }
}
