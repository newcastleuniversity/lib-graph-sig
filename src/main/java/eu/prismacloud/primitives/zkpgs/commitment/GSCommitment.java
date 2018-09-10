package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * The GSCommitment provides methods to compute commitments over one or more bases and exponents.
 */
public class GSCommitment implements Serializable {

	private static final long serialVersionUID = -6253701534775989050L;
	private final GroupElement commitmentValue;
	private final BaseCollection baseCollection;
	private final BigInteger randomness;

	private GSCommitment(final BaseCollection collection,
			final BigInteger rnd,
			final GroupElement commitment) {

		Assert.notNull(commitment, "commitment cannot be null");

		this.baseCollection = collection;
		this.randomness = rnd;
		this.commitmentValue = commitment;
	}


	/**
	 * Create commitment for one base and one message exponent using base S and modulus N.
	 *
	 * @param baseR the base R
	 * @param m     the message exponent
	 * @param rnd   the randomness
	 * @param baseS the base S
	 * @param modN  the modulus N
	 * @return the commitment
	 */
	public static GSCommitment createCommitment(GroupElement baseR, BigInteger m, BigInteger rnd, GroupElement baseS, BigInteger modN) {
		Assert.notNull(m, "message m cannot be null");
		Assert.notNull(baseR, "baseR cannot be null");
		Assert.notNull(rnd, "randomness cannot be null");
		Assert.notNull(modN, "modulus N cannot be null");

		GroupElement commimentValue = baseR.modPow(m).multiply(baseS.modPow(rnd));

		BaseRepresentation base = new BaseRepresentation(baseR, 0, BASE.ALL);
		base.setExponent(m);

		BaseCollection collection = new BaseCollectionImpl();
		collection.add(base);

		return new GSCommitment(collection, rnd, commimentValue);
	}


	/**
	 * Create commitment for one base and one message exponent using the ExtendedPublickey.
	 *
	 * @param m     the message exponent
	 * @param baseR the base R
	 * @param epk   the extended public key
	 * @return the commitment
	 */
	public static GSCommitment createCommitment(BigInteger m, ExtendedPublicKey epk) {
		Assert.notNull(m, "message m cannot be null");
		Assert.notNull(epk, "Extended public key cannot be null");

		KeyGenParameters keyGenParameters = epk.getPublicKey().getKeyGenParameters();

		// GroupElement message = baseR.modPow(m);

		// Establishing blinding
		BigInteger r = CryptoUtilsFacade.computeRandomNumberMinusPlus(
				keyGenParameters.getL_n() + keyGenParameters.getL_statzk());

		GroupElement baseS = epk.getPublicKey().getBaseS();
		Assert.notNull(baseS, "base S cannot be null");

		// GroupElement commitmentValue = message.multiply(blinding);
		GroupElement commimentValue = epk.getPublicKey().getBaseR().modPow(m).multiply(baseS.modPow(r));

		BaseRepresentation base = new BaseRepresentation(epk.getPublicKey().getBaseR(), -1, BASE.BASER);
		base.setExponent(m);
		
        BaseCollection collection = new BaseCollectionImpl();
        collection.add(base);

		return new GSCommitment(collection, r, commimentValue);
	}

	//    /**
	//     * Create commitment with a supplied map of bases and exponents, the randomness and the ExtendedPublicKey.
	//     *
	//     * @param basesR    the map of bases
	//     * @param exponents the map of exponents
	//     * @param rnd       the randomness
	//     * @param epk       the extended public key
	//     * @return the commitment
	//     * @deprecated
	//     * 
	//     * TODO this method does not work, because there is not guarantee that the two maps maintain the same order.
	//     */
	//    public static GSCommitment createCommitment(Map<URN, GroupElement> basesR,
	//                                                Map<URN, BigInteger> exponents, BigInteger rnd,
	//                                                ExtendedPublicKey epk) {
	//
	//        Assert.notNull(basesR, "base R cannot be null");
	//        Assert.notNull(exponents, "exponents cannot be null");
	//        Assert.notNull(rnd, "randomness cannot be null");
	//        Assert.notNull(epk, "Extended public key cannot be null");
	//        BigInteger modN = epk.getPublicKey().getModN();
	//        Assert.notNull(modN, "modulus N cannot be null");
	//
	//        GroupElement baseS = epk.getPublicKey().getBaseS();
	//        Assert.notNull(baseS, "base S cannot be null");
	//
	//        Group qrGroup = epk.getPublicKey().getQRGroup();
	//        BigInteger result = CryptoUtilsFacade.computeMultiBaseExpMap(basesR, exponents, modN);
	//        GroupElement commitmentValue = new QRElement(qrGroup, result).multiply(baseS.modPow(rnd));
	//
	//        return new GSCommitment(basesR, exponents, rnd, commitmentValue);
	//    }

	public static GSCommitment createCommitment(BaseCollection collection, BigInteger rnd, ExtendedPublicKey epk) {
		Assert.notNull(collection, "The base collection cannot be null.");
		Assert.notNull(rnd, "The randomness rnd cannot be null.");
		Assert.notNull(epk, "The extended public key cannot be null");

		KeyGenParameters keyGenParameters = epk.getPublicKey().getKeyGenParameters();

		// Establishing blinding
		BigInteger r = CryptoUtilsFacade.computeRandomNumberMinusPlus(
				keyGenParameters.getL_n() + keyGenParameters.getL_statzk());

		GroupElement baseS = epk.getPublicKey().getBaseS();
		Assert.notNull(baseS, "base S cannot be null");

		GroupElement commitmentValue = baseS.modPow(r);
		
		BaseIterator baseIter = collection.createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIter) {
			commitmentValue = commitmentValue.multiply(base.getBase().modPow(base.getExponent()));
		}

		return new GSCommitment(collection, r, commitmentValue);
	}


	/**
	 * Returns the commitment value.
	 *
	 * @return the commitment value
	 */
	public GroupElement getCommitmentValue() {
		return commitmentValue;
	}

	/**
	 * Returns a clone of the commitment's base collection.
	 * 
	 * @return base collection clone.
	 */
	public BaseCollection getBaseCollection() {
		return this.baseCollection.clone();
	}

	/**
	 * Returns randomness used for computing the commitment.
	 *
	 * @return the randomness
	 */
	public BigInteger getRandomness() {
		return randomness;
	}
	
	/**
	 * Returns a version of this commitment that only includes public information, 
	 * but neither secrets nor randomness.
	 * 
	 * @return a public commitment, which includes the commitment value and the base allocation used in the commitment.
	 */
	public GSCommitment clonePublicCommitment() {
		BaseCollection collection = new BaseCollectionImpl();
		BaseIterator secretCommitmentBases = this.baseCollection.createIterator(BASE.ALL);
		for (BaseRepresentation base : secretCommitmentBases) {
			// Secret exponents are not transfered or touched.
			BaseRepresentation newBase = new BaseRepresentation(base.getBase(), base.getBaseIndex(), base.getBaseType());
			collection.add(newBase);
		}
		
		// The randomness is intentionally set to null.
		return new GSCommitment(collection, null, this.getCommitmentValue());
	}

}
