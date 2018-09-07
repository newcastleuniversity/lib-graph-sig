package eu.prismacloud.primitives.zkpgs.util;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.*;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Vector;

/**
 * Wrapper for Utils class in IDEMIX library
 *
 * @see INumberUtils
 */
public class IdemixUtils extends Utils implements INumberUtils {

    private SystemParameters sp = null;
    private GroupParameters gp;
    private KeyGenParameters keyGenParameters;

    /**
     * Instantiates a new Idemix utils.
     *
     * @param keyGenParameters the key gen parameters
     */
    public IdemixUtils(KeyGenParameters keyGenParameters) {
        super();
        this.keyGenParameters = keyGenParameters;
    }

    public IdemixUtils() {
        super();
    }

    @Override
    public SafePrime generateRandomSafePrime(KeyGenParameters keyGenParameters) {
        BigInteger p =
                Utils.computeSafePrime(this.keyGenParameters.getL_n() / 2, this.keyGenParameters.getL_pt());
        BigInteger p_prime = p.subtract(BigInteger.ONE).shiftRight(1);

        return new SafePrime(p, p_prime);
    }

    @Override
    public SpecialRSAMod generateSpecialRSAModulus() {
        throw new RuntimeException("not currently used from idemix library");
    }

    /**
     * Algorithm <tt>alg:createElementOfZNS</tt> - topocert-doc Generate S' number
     *
     * <p>Dependencies: isElementOfZNS()
     *
     * @param modN the special RSA modulus
     * @return s_prime random number S' of QRN
     */
    public BigInteger createElementOfZNS(final BigInteger modN) {

        BigInteger s_prime;
        do {

            s_prime = createRandomNumber(NumberConstants.TWO.getValue(), modN.subtract(BigInteger.ONE));

        } while (!isElementOfZNS(s_prime, modN));

        return s_prime;
    }

    private boolean isElementOfZNS(final BigInteger s_prime, final BigInteger modN) {
        // check gcd(S', modN) = 1
        return (s_prime.gcd(modN).equals(BigInteger.ONE));
    }

    //  @Override
    //  public QRElement createQRNGenerator(final BigInteger n) {
    //    return new QRElement(Utils.computeGeneratorQuadraticResidue(n,
    // getIdemixSystemParameters()));
    //  }

    @Override
    public BigInteger createRandomNumber(final BigInteger lowerBound, final BigInteger upperBound) {
        return Utils.computeRandomNumber(lowerBound, upperBound, this.getIdemixSystemParameters());
    }

    @Override
    public BigInteger createRandomNumber(final int bitLength) {
        return Utils.computeRandomNumberSymmetric(bitLength);
    }

    @Override
    public CommitmentGroup generateCommitmentGroup() {

        StructureStore st = StructureStore.getInstance();
        st.add("idemix", this.getIdemixSystemParameters());

        try {
            gp = GroupParameters.generateGroupParams(new URI("idemix"));
        } catch (URISyntaxException e) {
            System.err.println("URI syntax is incorrect: " + e.getMessage());
        }

        return new CommitmentGroup(gp.getRho(), gp.getCapGamma(), gp.getG(), gp.getH());
    }

    @Override
    public BigInteger createCommitmentGroupGenerator(final BigInteger rho, final BigInteger gamma) {
        return GroupParameters.newGenerator(rho, gamma, getIdemixSystemParameters());
    }

    @Override
    public Boolean elementOfQRN(final BigInteger value, final BigInteger modulus) {
        throw new RuntimeException("not implemented in idemix library");
    }

    //  @Override
    //  public QRElement createQRNElement(final BigInteger n) {
    //    throw new RuntimeException("not implemented in idemix library");
    //  }

    @Override
    public BigInteger computeHash(List<String> list, int hashLength) throws NoSuchAlgorithmException {
        Vector<BigInteger> hlist = new Vector<BigInteger>();

        for (String element : list) {
            hlist.add(new BigInteger(element));
        }

        Vector<BigInteger> vlist = new Vector<BigInteger>(hlist);

        return Utils.hashOf(hashLength, vlist);
    }

    @Override
    public BigInteger computeA() {
        throw new RuntimeException("not implemented in idemix library");
    }

    @Override
    public BigInteger generateRandomPrime(int bitLength) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public BigInteger multiBaseExp(
            List<BigInteger> bases, List<BigInteger> exponents, BigInteger modN) {
        throw new RuntimeException("not currently used from idemix library");
    }

    //  @Override
    public BigInteger multiBaseExpMap(
            List<BigInteger> bases, List<BigInteger> exponents, BigInteger modN) {
        throw new RuntimeException("not implemented in idemix library");
    }

    @Override
    public BigInteger multiBaseExpMap(
            Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public BigInteger generatePrimeWithLength(int minBitLength, int maxBitLength) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public BigInteger randomMinusPlusNumber(int bitLength) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public GSSignature generateSignature(
            BigInteger m, BaseRepresentation base, SignerPublicKey signerPublicKey) {
        throw new RuntimeException("not currently used from idemix library");
    }

    private SystemParameters getIdemixSystemParameters() {

        if (sp == null) {
            sp =
                    new SystemParameters(
                            keyGenParameters.getL_e(),
                            keyGenParameters.getL_prime_e(),
                            keyGenParameters.getL_gamma(),
                            keyGenParameters.getL_H(),
                            0,
                            keyGenParameters.getL_m(),
                            keyGenParameters.getL_n(),
                            keyGenParameters.getL_statzk(),
                            keyGenParameters.getL_pt(),
                            keyGenParameters.getL_r(),
                            keyGenParameters.getL_res(),
                            keyGenParameters.getL_rho(),
                            keyGenParameters.getL_v(),
                            0);
        }
        return sp;
    }

    public boolean verifySGeneratorOfQRN(BigInteger s, BigInteger modN) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public BigInteger generatePrimeInRange(BigInteger min, BigInteger max) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public BigInteger getUpperPMBound(int bitLength) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public BigInteger getLowerPMBound(int bitLength) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public boolean isInPMRange(BigInteger number, int bitLength) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public boolean isInRange(BigInteger number, BigInteger min, BigInteger max) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public GroupElement computeMultiBaseExp(BaseCollection collection, BASE baseType, Group G) {
        throw new RuntimeException("not currently used from idemix library");
    }

    @Override
    public GroupElement computeMultiBaseExp(BaseCollection collection, Group G) {
        throw new RuntimeException("not currently used from idemix library");
    }
}
