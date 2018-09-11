package eu.prismacloud.primitives.zkpgs.integration;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
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
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Testing the prover side of the geo-location separation proof
 */
@EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
@TestInstance(Lifecycle.PER_CLASS)
public class GSProverServerTest {
    private Logger gslog = GSLoggerConfiguration.getGSlog();
    private KeyGenParameters keyGenParameters;
    private GraphEncodingParameters graphEncodingParameters;
    private ProverOrchestrator proverOrchestrator;
    private ExtendedPublicKey extendedPublicKey;
    private FilePersistenceUtil persistenceUtil;
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
    private GSSignature sig;
    private String gsSignatureFileName;

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

        gsSignatureFileName = "signer-infra.gs.ser";
        sig = (GSSignature) persistenceUtil.read(gsSignatureFileName);

        gslog.info("read encoded base collection");
        baseCollection = sig.getEncodedBases();
//        gslog.info("bases: " + baseCollection.getStringOverview());

        proofStore = new ProofStore<>();
    }

    @EnabledOnSuite(name = GSSuite.PROVER_VERIFIER)
    @Test
    void testProverSide() throws Exception {

        proverOrchestrator = new ProverOrchestrator(extendedPublicKey);
        proverOrchestrator.readSignature(gsSignatureFileName);
        proverOrchestrator.init();
        proverOrchestrator.executePreChallengePhase();
        BigInteger cChallenge = proverOrchestrator.computeChallenge();
        assertNotNull(cChallenge);
        proverOrchestrator.executePostChallengePhase(cChallenge);
        proverOrchestrator.close();
    }

}
