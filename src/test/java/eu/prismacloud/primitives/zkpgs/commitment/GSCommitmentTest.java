package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementN;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GSCommitmentTest {

    private GSCommitment commitment;
    private Map<URN, GroupElement> basesR;
    private Map<URN, BigInteger> exponents;
    private BigInteger modN;
    private GroupElement R_0;
    private GroupElement R_1;
    private BigInteger m_0;
    private BigInteger m_1;
    private GroupElement R_2;
    private BigInteger m_2;
    private ExtendedPublicKey epk;
    private BigInteger randomness;

    @BeforeAll
    void setupKey() throws IOException, ClassNotFoundException, EncodingException {
        BaseTest baseTest = new BaseTest();
        baseTest.setup();
        baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
        SignerKeyPair skp = baseTest.getSignerKeyPair();
        GraphEncodingParameters graphEncodingParameters = baseTest.getGraphEncodingParameters();
        KeyGenParameters keyGenParameters = baseTest.getKeyGenParameters();
        ExtendedKeyPair extendedKeyPair = new ExtendedKeyPair(skp, graphEncodingParameters, keyGenParameters);
        extendedKeyPair.generateBases();
        extendedKeyPair.setupEncoding();
        extendedKeyPair.createExtendedKeyPair();
        epk = extendedKeyPair.getExtendedPublicKey();
    }

    @BeforeEach
    void setUp() {
        basesR = new HashMap<URN, GroupElement>();
        exponents = new HashMap<URN, BigInteger>();
        randomness = BigInteger.TEN;

        R_0 = new QRElementN(epk.getPublicKey().getQRGroup(), BigInteger.valueOf(58));
        R_1 = new QRElementN(epk.getPublicKey().getQRGroup(), BigInteger.valueOf(29));
        R_2 = new QRElementN(epk.getPublicKey().getQRGroup(), BigInteger.valueOf(79));

        basesR.put(URN.createZkpgsURN("test.base.0"), R_0);
        basesR.put(URN.createZkpgsURN("test.base.1"), R_1);
        basesR.put(URN.createZkpgsURN("test.base.2"), R_2);

        m_0 = BigInteger.valueOf(44);
        m_1 = BigInteger.valueOf(89);
        m_2 = BigInteger.valueOf(59);

        exponents.put(URN.createZkpgsURN("test.exponent.0"), m_0);
        exponents.put(URN.createZkpgsURN("test.exponent.1"), m_1);
        exponents.put(URN.createZkpgsURN("test.exponent.2"), m_2);
        commitment = GSCommitment.createCommitment(basesR, exponents, randomness, epk);
    }

    @Test
    @DisplayName("Test computing a commitment with multiple bases and exponents with extended public key")
    void testcomputeCommitmentMultiBase() {

        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(R_1.modPow(m_1)).multiply(R_2.modPow(m_2)).multiply(epk.getPublicKey().getBaseS().modPow(randomness));

        assertEquals(result, commitment.getCommitmentValue());
    }


    @Test
    @DisplayName("Test computing a commitment with  base and exponent when using modN and base S")
    void testcomputeCommitment() {
        GSCommitment commitment = GSCommitment.createCommitment(R_0, m_0, randomness, epk.getPublicKey().getBaseS(), epk.getPublicKey().getModN());
        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(epk.getPublicKey().getBaseS().modPow(randomness));

        assertEquals(result, commitment.getCommitmentValue());
    }

    @Test
    @DisplayName("Test computing a commitment with  base and exponent when using EPK")
    void testcomputeCommitmentWithEPK() {
        GSCommitment commitment = GSCommitment.createCommitment( m_0, R_0, epk);
        assertNotNull(commitment);
        GroupElement result = R_0.modPow(m_0).multiply(epk.getPublicKey().getBaseS().modPow(commitment.getRandomness()));

        assertEquals(result, commitment.getCommitmentValue());
    }
    @Test
    @DisplayName("Test returning commitment value")
    void getCommitmentValue() {
        GroupElement commitmentValue = commitment.getCommitmentValue();
        assertNotNull(commitmentValue);

    }

    @Test
    @DisplayName("Test returning map of bases")
    void getBasesR() {
        Map<URN, GroupElement> bases = commitment.getBasesR();
        assertNotNull(bases);
        assertTrue(!bases.isEmpty());
    }

    @Test
    @DisplayName("Test returning map of exponents")
    void getExponents() {
        Map<URN, BigInteger> exponents = commitment.getExponents();
        assertNotNull(exponents);
        assertTrue(!exponents.isEmpty());

    }

    @Test
    @DisplayName("Test returning map of randomness")
    void getRandomness() {
        BigInteger rand = commitment.getRandomness();
        assertNotNull(rand);
        assertEquals(BigInteger.TEN, rand);
    }
}