package eu.prismacloud.primitives.zkpgs.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.EnabledOnSuite;
import eu.prismacloud.primitives.zkpgs.GSSuite;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.orchestrator.ProverOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupPQ;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** Testing the prover side of the geo-location separation proof */
@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
@TestInstance(Lifecycle.PER_CLASS)
public class GSProverServerTest {

  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private ProverOrchestrator proverOrchestrator;
  private ExtendedPublicKey extendedPublicKey;
  private FilePersistenceUtil persistenceUtil;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private GroupElement A;
  private BigInteger e;
  private BigInteger v;
  private BaseCollection baseCollection;
  private SignerPublicKey publicKey;
  private SignerKeyPair signerKeyPair;
  private SignerPrivateKey privateKey;
  private GSSignature gsSignature;
  private BigInteger m_0;
  private GSCommitment commitment;
  private Iterator<BaseRepresentation> vertexIterator;
  private ProofStore<Object> proofStore;

  @BeforeAll
  void setupKey()
      throws IOException, ClassNotFoundException, InterruptedException, ProofStoreException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();

    gslog.info("read ExtendedPublicKey...");

    String signerKeyPairFileName = "SignerKeyPair-" + keyGenParameters.getL_n() + ".ser";
    signerKeyPair = (SignerKeyPair) persistenceUtil.read(signerKeyPairFileName);
    privateKey = signerKeyPair.getPrivateKey();

    String extendedPublicKeyFileName = "ExtendedPublicKey-" + keyGenParameters.getL_n() + ".ser";
    extendedPublicKey = (ExtendedPublicKey) persistenceUtil.read(extendedPublicKeyFileName);
    publicKey = extendedPublicKey.getPublicKey();
    gslog.info("read persisted graph signature");
    A = (GroupElement) persistenceUtil.read("A.ser");
    e = (BigInteger) persistenceUtil.read("e.ser");
    v = (BigInteger) persistenceUtil.read("v.ser");

    gslog.info("read encoded base collection");
    baseCollection = (BaseCollection) persistenceUtil.read("baseCollection.ser");
    vertexIterator = baseCollection.createIterator(BASE.VERTEX).iterator();
    proofStore = new ProofStore<>();
    generateTestSignature(proofStore);
  }

  @EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
  @Test
  void testProverSide() throws Exception {

    BaseRepresentation baseR0 =
        new BaseRepresentation(extendedPublicKey.getPublicKey().getBaseR_0(), -1, BASE.BASE0);
    baseR0.setExponent(m_0);

    baseCollection = new BaseCollectionImpl();
    baseCollection.add(baseR0);
    BaseRepresentation baseR1 = (BaseRepresentation) vertexIterator.next();
    BaseRepresentation baseR2 = (BaseRepresentation) vertexIterator.next();

    baseCollection.add(baseR1);
    baseCollection.add(baseR2);

    proofStore.store("encoded.bases", baseCollection);

    proverOrchestrator =
        new ProverOrchestrator(
            extendedPublicKey, proofStore, keyGenParameters, graphEncodingParameters);
    proverOrchestrator.init();
    proverOrchestrator.computePreChallengePhase();
    proverOrchestrator.computeChallenge();
    proverOrchestrator.computePostChallengePhase();
    proverOrchestrator.close();
  }

  void generateTestSignature(ProofStore<Object> proofStore) throws ProofStoreException {
    BigInteger modN = publicKey.getModN();
    m_0 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
    proofStore.store("recipient.m_0", m_0);

    GroupElement baseS = publicKey.getBaseS();
    GroupElement baseZ = publicKey.getBaseZ();
    GroupElement R_0 = publicKey.getBaseR_0();
    QRGroupPQ qrGroupPQ = (QRGroupPQ) publicKey.getQRGroup();

    BigInteger vbar = CryptoUtilsFacade.computeRandomNumberMinusPlus(keyGenParameters.getL_v() - 1);
    GroupElement R_0com = R_0.modPow(m_0);
    GroupElement baseScom = baseS.modPow(vbar);
    GroupElement commitmentValue = R_0com.multiply(baseScom);
    commitment = new GSCommitment(R_0, m_0, vbar, baseS, modN);

    e =
        CryptoUtilsFacade.computePrimeInRange(
            keyGenParameters.getLowerBoundE(), keyGenParameters.getUpperBoundE());

    BigInteger vPrimePrime =
        CryptoUtilsFacade.computePrimeInRange(
            keyGenParameters.getLowerBoundV(), keyGenParameters.getUpperBoundV());

    GroupElement Sv = baseS.modPow(vPrimePrime);
    GroupElement Sv1 = (Sv.multiply(commitmentValue));
    GroupElement Q = (baseZ.multiply(Sv1.modInverse()));

    BigInteger order = privateKey.getpPrime().multiply(privateKey.getqPrime());
    BigInteger d = e.modInverse(order);
    A = Q.modPow(d);
    GroupElement sigma = A.modPow(e);
    assertEquals(sigma, Q, "Signature A not reverting to Q.");

    gsSignature = new GSSignature(signerKeyPair.getPublicKey(), A, e, vPrimePrime);
    assertTrue(gsSignature.verify(signerKeyPair.getPublicKey(), commitmentValue));

    proofStore.store("graphsignature.A", gsSignature.getA());
    proofStore.store("graphsignature.e", gsSignature.getE());
    proofStore.store("graphsignature.v", gsSignature.getV());
  }
}
