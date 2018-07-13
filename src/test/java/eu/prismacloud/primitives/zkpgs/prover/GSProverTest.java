package eu.prismacloud.primitives.zkpgs.prover;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GSProverTest {

  private SignerKeyPair signerKeyPair;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ProofStore<Object> proofStore;
  private SignerPublicKey publicKey;
  private GSProver prover;
  private BigInteger testMessage;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    signerKeyPair = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(signerKeyPair, graphEncodingParameters, keyGenParameters);
    publicKey = signerKeyPair.getPublicKey();

  }

  @BeforeEach
  void setup(){
    proofStore = new ProofStore<Object>();
        prover = new GSProver(publicKey.getModN(), publicKey.getBaseS(), proofStore, keyGenParameters);
  }

  @Test
  void getCommitmentMap() throws Exception {
    BaseRepresentation baseRepresentation =
        new BaseRepresentation(publicKey.getBaseR(), 0, BASE.VERTEX);
    testMessage = CryptoUtilsFacade.generateRandomPrime(keyGenParameters.getL_m());
    baseRepresentation.setExponent(testMessage);
    Map<URN, BaseRepresentation> baseRepresentationMap = new HashMap<>();
    baseRepresentationMap.put(URN.createZkpgsURN("base.test"), baseRepresentation);

    prover.computeCommitments(baseRepresentationMap);
    Map<URN, GSCommitment> cMap = prover.getCommitmentMap();

    assertNotNull(cMap);
    assertEquals(1, cMap.size());
  }

  @Test
  void computeCommitments() throws Exception {
    BaseRepresentation baseRepresentation =
        new BaseRepresentation(publicKey.getBaseR(), 0, BASE.VERTEX);
    testMessage = CryptoUtilsFacade.generateRandomPrime(keyGenParameters.getL_m());
        baseRepresentation.setExponent(testMessage);
    Map<URN, BaseRepresentation> baseRepresentationMap = new HashMap<>();
    baseRepresentationMap.put(URN.createZkpgsURN("base.test"), baseRepresentation);

    prover.computeCommitments(baseRepresentationMap);
    Map<URN, GSCommitment> cMap = prover.getCommitmentMap();
  }

  @Test
  void computeBlindedSignature() {}

  @Test
  void sendMessage() {}
}
