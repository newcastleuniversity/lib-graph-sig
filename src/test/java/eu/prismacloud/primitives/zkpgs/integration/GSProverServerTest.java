package eu.prismacloud.primitives.zkpgs.integration;

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
import eu.prismacloud.primitives.zkpgs.signer.GSSigningOracle;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
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
  private GSSigningOracle oracle;
  private GSSignature sigmaM;

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

    oracle = new GSSigningOracle(signerKeyPair, keyGenParameters);

    //    A = (GroupElement) persistenceUtil.read("A.ser");
    //    e = (BigInteger) persistenceUtil.read("e.ser");
    //    v = (BigInteger) persistenceUtil.read("v.ser");

    gslog.info("read encoded base collection");
    baseCollection = (BaseCollection) persistenceUtil.read("baseCollection.ser");
    vertexIterator = baseCollection.createIterator(BASE.VERTEX).iterator();
    proofStore = new ProofStore<>();
  }

  @EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
  @Test
  void testProverSide() throws Exception {

    m_0 = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
    proofStore.store("recipient.m_0", m_0);
    sigmaM = oracle.sign(m_0);
    storeGS(sigmaM);

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
            extendedPublicKey);
    proverOrchestrator.init();
    proverOrchestrator.executePreChallengePhase();
    BigInteger cChallenge = proverOrchestrator.computeChallenge();
    proverOrchestrator.executePostChallengePhase(cChallenge);
    proverOrchestrator.close();
  }

  private void storeGS(GSSignature sigma) throws Exception {
    String gsURN = "graphsignature";
    proofStore.store(gsURN, sigma);

    String AURN = "graphsignature.A";
    proofStore.store(AURN, sigma.getA());

    String eURN = "graphsignature.e";
    proofStore.store(eURN, sigma.getE());

    String vPrimeURN = "graphsignature.v";
    proofStore.store(vPrimeURN, sigma.getV());
  }
}
