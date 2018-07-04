package eu.prismacloud.primitives.zkpgs.orchestrator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.verifier.GroupSetupVerifier;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.logging.Logger;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/** */
class SignerOrchestratorTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private GroupSetupVerifier groupSetupVerifier;
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private SignerKeyPair gsk;
  private ExtendedKeyPair extendedKeyPair;
  private GroupSetupProver groupSetupProver;
  private ProofStore<Object> proofStore;
  private BigInteger tilder;
  private BigInteger tilder_0;
  private BigInteger tilder_Z;
  private BigInteger hatr_Z;
  private BigInteger hatr;
  private BigInteger hatr_0;
  private ProofSignature proofSignature;
  private SignerOrchestrator signerOrchestrator;
  private RecipientOrchestrator recipientOrchestrator;
  private BigInteger e;
  private BigInteger R_0;
  private BigInteger R_0com;
  private BigInteger modN;
  private BigInteger m_0;
  private BigInteger baseS;
  private BigInteger vCommRandomness;
  private BigInteger baseScom;
  private BigInteger vbar;
  private BigInteger vPrimePrime;
  private BigInteger commitment;
  private BigInteger baseZ;
  private BigInteger Q;
  private BigInteger d;
  private BigInteger A;
  private BigInteger x_Z;
  private BigInteger Sv;
  private BigInteger Sv1;
  private BigInteger ZPrime;
  private BigInteger R_0multi;
  private SignerPrivateKey privateKey;
  private BigInteger order;

  //  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, ProofStoreException {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
    log.info("@Test: key generation");
    gsk = SignerKeyPair.KeyGen(keyGenParameters);
    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());

    groupSetupProver = new GroupSetupProver();
    proofStore = new ProofStore<Object>();

    groupSetupProver.preChallengePhase(
        extendedKeyPair, proofStore, keyGenParameters, graphEncodingParameters);
    tilder = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder");

    tilder_0 = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_0");

    tilder_Z = (BigInteger) proofStore.retrieve("groupsetupprover.witnesses.randomness.tilder_Z");

    assertNotNull(tilder);
    assertNotNull(tilder_0);
    assertNotNull(tilder_Z);

    BigInteger cChallenge = groupSetupProver.computeChallenge();

    //    assertEquals(cChallenge.bitLength(), keyGenParameters.getL_H());

    groupSetupProver.postChallengePhase();

    hatr_Z = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_Z");
    hatr = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr");
    hatr_0 = (BigInteger) proofStore.retrieve("groupsetupprover.responses.hatr_0");

    assertNotNull(hatr_Z);
    assertNotNull(hatr);
    assertNotNull(hatr_0);

    int bitLength = computeBitLength();

    //    assertEquals(bitLength, hatr_Z.bitLength());
    //    assertEquals(bitLength, hatr.bitLength());
    //    assertEquals(bitLength, hatr_0.bitLength());

    proofSignature = groupSetupProver.outputProofSignature();
    Map<URN, Object> proofElements = proofSignature.getProofSignatureElements();
    assertNotNull(proofSignature);
    assertNotNull(proofSignature.getProofSignatureElements());

    for (Object element : proofElements.values()) {
      assertNotNull(element);
    }

    BigInteger phatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");
    //    assertEquals(bitLength, phatr.bitLength());

    BigInteger phatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
    //    assertEquals(bitLength, phatr_0.bitLength());
    BigInteger phatr_Z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
    //    assertEquals(bitLength, phatr_Z.bitLength());

    Map<URN, BigInteger> edgeResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
    Map<URN, BigInteger> vertexResponses =
        (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");

    for (BigInteger vertexResponse : vertexResponses.values()) {
      //      assertEquals(bitLength, vertexResponse.bitLength());
    }

    for (BigInteger edgeResponse : edgeResponses.values()) {
      //      assertEquals(bitLength, edgeResponse.bitLength());
    }

    groupSetupVerifier = new GroupSetupVerifier();

    groupSetupVerifier.preChallengePhase(
        extendedKeyPair.getExtendedPublicKey(),
        proofSignature,
        proofStore,
        keyGenParameters,
        graphEncodingParameters);

    groupSetupVerifier.checkLengths();

    groupSetupVerifier.computeHatValues();

    groupSetupVerifier.computeVerificationChallenge();

    groupSetupVerifier.verifyChallenge();

    signerOrchestrator =
        new SignerOrchestrator(extendedKeyPair, keyGenParameters, graphEncodingParameters);

    recipientOrchestrator =
        new RecipientOrchestrator(
            extendedKeyPair.getExtendedPublicKey(), keyGenParameters, graphEncodingParameters);

    assertNotNull(signerOrchestrator);
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }

  @Test
  void round0() throws Exception {
    signerOrchestrator.round0();

    recipientOrchestrator.round1();

    signerOrchestrator.round2();

    recipientOrchestrator.round3();

    //    recipientOrchestrator.round3();

  }

  @Test
  @RepeatedTest(10)
  void testGRSignatureRandom() {

    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
    log.info("@Test: key generation");
    gsk = SignerKeyPair.KeyGen(keyGenParameters);
    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());

    privateKey = extendedKeyPair.getExtendedPrivateKey().getPrivateKey();

    groupSetupProver = new GroupSetupProver();
    proofStore = new ProofStore<Object>();

    modN = extendedKeyPair.getPublicKey().getModN();
    m_0 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
    baseS = extendedKeyPair.getExtendedPublicKey().getPublicKey().getBaseS().getValue();

    baseZ = extendedKeyPair.getExtendedPublicKey().getPublicKey().getBaseZ().getValue();

    R_0 = extendedKeyPair.getExtendedPublicKey().getPublicKey().getBaseR_0().getValue();

    vbar = CryptoUtilsFacade.computeRandomNumberMinusPlus(keyGenParameters.getL_v() - 1);
    R_0com = R_0.modPow(m_0, modN);
    baseScom = baseS.modPow(vbar, modN);
    commitment = R_0com.multiply(baseScom).mod(modN);

    //    log.info("recipient R_0:  " + R_0);
    //    log.info("recipient m_0: " + m_0);
    //    log.info("commitment: " + commitment);

    calculateSignatureRandom();
  }

  private void calculateSignatureRandom() {
    computeQRandom();
    computeARandom();
    verifySignatureRandom();
  }

  private void computeQRandom() {
    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);
    vbar = CryptoUtilsFacade.computeRandomNumberMinusPlus(keyGenParameters.getL_v() - 1);

    log.info("e bitlength: " + e.bitLength());
    log.info("vbar bitlength: " + vbar.bitLength());

    vPrimePrime =
        vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);

    log.info("vPrimePrime bitlength: " + vPrimePrime.bitLength());

    //    log.info("vbar: " + vbar);
    //    log.info("vPrimePrime: " + vPrimePrime);

    Sv = baseS.modPow(vPrimePrime, modN);
    R_0multi = R_0.modPow(m_0, modN);
    Sv1 = Sv.multiply(R_0multi);

    Q = baseZ.multiply(Sv1.modInverse(modN));

    log.info(" Q bitlength: " + Q.bitLength());
    log.info(" e bitlength: " + e.bitLength());
    log.info(" Z bitlength: " + baseZ.bitLength());
    log.info(" S bitlegth: " + baseS.bitLength());

    //    log.info("signer Q: " + Q);
    //     log.info("signer e: " + e);
    //     log.info("signer Z: " + baseZ);
    //     log.info("signer S: " + baseS);
  }

  private void computeARandom() {
    order = privateKey.getpPrime().multiply(privateKey.getqPrime());

    d = e.modInverse(order);
    A = Q.modPow(d, modN);

//    log.info("d: " + d);

//    log.info("A: " + A);
  }

  private void verifySignatureRandom() {

    //    log.info("recipient.R_0: " + R_0);
    //
    //    log.info("recipient.m_0: " + m_0);

    ZPrime = A.modPow(e, modN).multiply(baseS.modPow(vPrimePrime, modN));

    BigInteger hatZ = ZPrime.multiply(R_0multi).mod(modN);
    log.info("Z:" + baseZ);

    log.info("hatZ: " + hatZ);
    log.info("hatZ bitlength: " + hatZ.bitLength());
    log.info("Z bitlength:" + baseZ.bitLength());
    
    assertEquals(baseZ, hatZ.mod(modN));
  }

  @Test
  void testSignatureGeneration() throws Exception {

    //    N =77, l_n = 7
    //    p = 11, p’ =5; q = 7, q’ = 3
    //
    //    \phi(N) = 60
    //    S = 60; QR_N = <60>; order of QR_N = 15
    //    R = 58
    //
    //    l_m = 2; l_e =4 (of course there are only 2 primes e possible fitting these parameters, 11
    // and 13, and the only messages possible: 1, 2 or 3).

    modN = BigInteger.valueOf(77);
    m_0 = BigInteger.valueOf(3);
    baseS = BigInteger.valueOf(60);

    x_Z = CryptoUtilsFacade.computeRandomNumber(BigInteger.valueOf(2), BigInteger.valueOf(14));
    baseZ = baseS.modPow(x_Z, modN);

    R_0 = BigInteger.valueOf(58);

    vCommRandomness = BigInteger.valueOf(2);
    R_0com = R_0.modPow(m_0, modN);
    baseScom = baseS.modPow(vCommRandomness, modN);
    commitment = R_0com.multiply(baseScom).mod(modN);

    log.info("recipient R_0:  " + R_0);
    log.info("recipient m_0: " + m_0);
    log.info("commitment: " + commitment);

    calculateSignature();
  }

  void calculateSignature() throws Exception {
    computeQ();
    computeA();
    verifySignature();
  }

  void computeQ() {
    e = BigInteger.valueOf(13);
    vbar = CryptoUtilsFacade.computeRandomNumberMinusPlus(429 - 1);
    vPrimePrime = NumberConstants.TWO.getValue().pow(429 - 1).add(vbar);

    log.info("vbar: " + vbar);
    log.info("vPrimePrime: " + vPrimePrime);

    Sv = baseS.modPow(vPrimePrime, modN);
    R_0multi = R_0.modPow(m_0, modN);
    Sv1 = Sv.multiply(R_0multi);

    Q = baseZ.multiply(Sv1.modInverse(modN));

    log.info("signer Q: " + Q);
    log.info("signer e: " + e);
    log.info("signer Z: " + baseZ);
    log.info("signer S: " + baseS);
  }

  void computeA() {
    d = e.modInverse(BigInteger.valueOf(15));
    A = Q.modPow(d, modN);

    log.info("d: " + d);

    log.info("A: " + A);
  }

  void verifySignature() throws Exception {

    BigInteger vPrime = CryptoUtilsFacade.computeRandomNumberMinusPlus(87);
    log.info("signer vPrime: " + vPrime);

    BigInteger v = vPrimePrime.add(vPrime);

    log.info("recipient.R_0: " + R_0);

    log.info("recipient.m_0: " + m_0);

    BigInteger R_0multi = R_0.modPow(m_0, modN);
    BigInteger Ae = A.modPow(e, modN);
    BigInteger baseSmulti = baseS.modPow(v, modN);
    ZPrime = A.modPow(e, modN).multiply(baseS.modPow(vPrimePrime, modN));

    BigInteger hatZ = ZPrime.multiply(R_0multi).mod(modN);

    log.info("signer hatZ: " + hatZ);

    assertEquals(baseZ, hatZ.mod(modN));
  }

  @Test
  void round2() {}

  @Test
  void computeChallenge() {}

  @Test
  void verifyChallenge() {}

  @Test
  void createPartialSignature() {}

  @Test
  void computeRandomness() {}

  @Test
  void computevPrimePrime() {}

  @Test
  void store() {}
}
