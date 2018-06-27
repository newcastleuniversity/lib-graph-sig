package eu.prismacloud.primitives.zkpgs.util;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
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

  /** Instantiates a new Idemix utils. */
  public IdemixUtils() {
    super();
  }

  @Override
  public SafePrime generateRandomSafePrime() {
    BigInteger p =
        Utils.computeSafePrime(keyGenParameters.getL_n() / 2, keyGenParameters.getL_pt());
    BigInteger p_prime = p.subtract(BigInteger.ONE).shiftRight(1);

    return new SafePrime(p, p_prime);
  }

  @Override
  public SpecialRSAMod generateSpecialRSAModulus() {
    return null;
  }

  @Override
  public BigInteger createQRNGenerator(final BigInteger n) {
    return Utils.computeGeneratorQuadraticResidue(n, getIdemixSystemParameters());
  }

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

  @Override
  public BigInteger createQRNElement(final BigInteger n) {
    throw new RuntimeException("not implemented in idemix library");
  }

  @Override
  public BigInteger computeHash(List<String> list, int hashLength) throws NoSuchAlgorithmException {
    Vector<BigInteger> hlist = new Vector<BigInteger>();
    BigInteger value;

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
  public BigInteger multiBaseExp(Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN) {
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
  public GSSignature generateSignature(BigInteger m, BaseRepresentation base,
      SignerPublicKey signerPublicKey) {
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
}
