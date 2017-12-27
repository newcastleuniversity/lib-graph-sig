package eu.prismacloud.primitives.grs.utils;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Wrapper for Utils class in IDEMIX  library
 */
public class IdemixUtils extends Utils implements INumberUtils {

    private Utils utils;
    private SystemParameters sp = null;
    private GroupParameters gp;

    public IdemixUtils() {
        super();
    }

    @Override
    public SafePrime generateRandomSafePrime() {
        BigInteger p = Utils.computeSafePrime(KeyGenParameters.l_n.getValue() / 2, KeyGenParameters.l_pt.getValue());
        BigInteger p_prime = p.subtract(BigInteger.ONE).shiftRight(1);

        return new SafePrime(p, p_prime);

    }

    @Override
    public SpecialRSAMod generateSpecialRSAModulus() {
        return null;
    }

    @Override
    public BigInteger createQRNGenerator(BigInteger n) {
        return null;
    }

//    @Override
//    public BigInteger createQRNGenerator() {
//        return null;
//    }

    @Override
    public BigInteger createRandomNumber(final BigInteger lowerBound, final BigInteger upperBound) {
        return Utils.computeRandomNumber(lowerBound, upperBound, this.getSP());
    }

    @Override
    public CommitmentGroup generateCommitmentGroup() {
        StructureStore st = StructureStore.getInstance();
        st.add("idemix", this.getSP());

        GroupParameters gp = null;
        try {
            gp = GroupParameters.generateGroupParams(new URI("idemix"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        return new CommitmentGroup(gp.getRho(), gp.getCapGamma(), gp.getG(), gp.getH());

    }

    @Override
    public BigInteger createCommitmentGroupGenerator(BigInteger rho, BigInteger gamma) {
       throw new RuntimeException("not implemented");
    }

    @Override
    public Boolean elementOfQR(BigInteger value, BigInteger modulus) {
        throw new RuntimeException("not implemented");
    }

    private SystemParameters getSP() {

        if (sp == null) {
            sp = new SystemParameters(KeyGenParameters.l_e.getValue(), KeyGenParameters.l_prime_e.getValue(), KeyGenParameters.l_gamma.getValue(), KeyGenParameters.l_H.getValue(), 0, KeyGenParameters.l_m.getValue(), KeyGenParameters.l_n.getValue(), KeyGenParameters.l_0.getValue(), KeyGenParameters.l_pt.getValue(), KeyGenParameters.l_r.getValue(), KeyGenParameters.l_res.getValue(), KeyGenParameters.l_rho.getValue(), KeyGenParameters.l_v.getValue(), 0);
            return sp;
        } else return this.sp;

    }
}
