package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.io.Serializable;
import java.math.BigInteger;

import eu.prismacloud.primitives.zkpgs.PublicCloneable;
import eu.prismacloud.primitives.zkpgs.exception.GSInternalError;

/** Special RSA Modulus class */
public class SpecialRSAMod implements Serializable, Cloneable, PublicCloneable {

	private static final long serialVersionUID = -8028993096815931923L;

	private final BigInteger modN;
	private BigInteger p;
	private BigInteger q;
	private BigInteger pPrime;
	private BigInteger qPrime;
	private SafePrime sp;
	private SafePrime sq;

	/**
	 * Instantiates a new Special RSA mod.
	 *
	 * @param modN the mod n
	 * @param p the p
	 * @param q the q
	 * @param pPrime the p prime
	 * @param qPrime the q prime
	 */
	public SpecialRSAMod(
			BigInteger modN, BigInteger p, BigInteger q, BigInteger pPrime, BigInteger qPrime) {

		this.modN = modN;
		this.p = p;
		this.q = q;
		this.pPrime = pPrime;
		this.qPrime = qPrime;
	}

	/**
	 * Instantiates a new Special RSA mod.
	 *
	 * @param modN the mod n
	 * @param sp the sp
	 * @param sq the sq
	 */
	public SpecialRSAMod(BigInteger modN, SafePrime sp, SafePrime sq) {
		this.modN = modN;
		this.sp = sp;
		this.sq = sq;
	}
	
	/**
	 * Instantiates a new PUBLIC Special RSA mod.
	 *
	 * @param modN the mod N
	 * @param sp the sp
	 * @param sq the sq
	 */
	public SpecialRSAMod(BigInteger modN) {
		this.modN = modN;
	}

	/**
	 * Gets modulus n.
	 *
	 * @return the n
	 */
	public BigInteger getN() {
		return modN;
	}

	/**
	 * Gets p.
	 *
	 * @return the p
	 */
	public BigInteger getP() {
		return sp.getSafePrime();
	}

	/**
	 * Gets q.
	 *
	 * @return the q
	 */
	public BigInteger getQ() {
		return sq.getSafePrime();
	}

	/**
	 * Gets prime.
	 *
	 * @return the prime
	 */
	public BigInteger getpPrime() {
		return sp.getSophieGermain();
	}

	/**
	 * Gets prime.
	 *
	 * @return the prime
	 */
	public BigInteger getqPrime() {
		return sq.getSophieGermain();
	}

	public SpecialRSAMod publicClone() {
		return new SpecialRSAMod(this.modN);
	}

	@Override
	public CommitmentGroup clone() {
		CommitmentGroup theClone = null;

		try {
			theClone = (CommitmentGroup) super.clone();
		} catch (CloneNotSupportedException e) {
			// Should never happen
			throw new GSInternalError(e);
		}
		return theClone;
	}
}
