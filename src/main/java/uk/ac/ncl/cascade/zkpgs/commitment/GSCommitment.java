package uk.ac.ncl.cascade.zkpgs.commitment;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.PublicCloneable;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollectionImpl;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * The GSCommitment provides methods to compute commitments over one or more bases and exponents.
 */
public class GSCommitment implements Serializable, PublicCloneable {

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

	public static GSCommitment createCommitment(BaseCollection collection, BigInteger rnd, ExtendedPublicKey epk) {
		Assert.notNull(collection, "The base collection cannot be null.");
		Assert.notNull(rnd, "The randomness rnd cannot be null.");
		Assert.notNull(epk, "The extended public key cannot be null");

		KeyGenParameters keyGenParameters = epk.getPublicKey().getKeyGenParameters();

		GroupElement baseS = epk.getPublicKey().getBaseS();
		Assert.notNull(baseS, "base S cannot be null");

		GroupElement commitmentValue = baseS.modPow(rnd);
		
		BaseIterator baseIter = collection.createIterator(BASE.ALL);
		for (BaseRepresentation base : baseIter) {
			commitmentValue = commitmentValue.multiply(base.getBase().modPow(base.getExponent()));
		}

		return new GSCommitment(collection, rnd, commitmentValue);
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
	public GSCommitment publicClone() {
		BaseCollection collection = new BaseCollectionImpl();
		BaseIterator secretCommitmentBases = this.baseCollection.createIterator(BASE.ALL);
		for (BaseRepresentation base : secretCommitmentBases) {
			// Secret exponents are not transfered or touched.
			BaseRepresentation newBase = new BaseRepresentation(base.getBase(), base.getBaseIndex(), base.getBaseType());
			newBase.setExponent(BigInteger.ONE);
			collection.add(newBase);
		}
		
		// The randomness is intentionally set to null.
		return new GSCommitment(collection, null, this.getCommitmentValue());
	}

}
