package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.exception.GSInternalError;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;

/** Commitment Group value class */
public final class CommitmentGroup extends Group {
	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 2729550023481194427L;
	
	
	/** order of the subgroup of the commitment group /( \rho \) */
	private BigInteger rho;
	/** commitment group modulus /( \Gamma \) */
	private BigInteger gamma;

	private CommitmentGroupElement g;
	private BigInteger r;
	private CommitmentGroupElement h;

	public CommitmentGroup(
			final BigInteger rho, final BigInteger gamma, final BigInteger g, BigInteger h) {

		this.rho = rho;
		this.gamma = gamma;
		this.g = new CommitmentGroupElement(this, g);
		this.h = new CommitmentGroupElement(this, h);
	}

	public BigInteger getRho() {
		return rho;
	}

	public BigInteger getGamma() {
		return gamma;
	}

	public BigInteger getG() {
		return g.getValue();
	}

	public BigInteger getH() {
		return h.getValue();
	}

	@Override
	public BigInteger getOrder() {
		return gamma.subtract(BigInteger.ONE);
	}

	@Override
	public GroupElement getGenerator() {
		return this.g;
	}

	@Override
	public BigInteger getModulus() {
		return this.gamma;
	}

	public GroupElement createGenerator(BigInteger rho, BigInteger gamma) {
		return this.g =
				new CommitmentGroupElement(this, CryptoUtilsFacade.commitmentGroupGenerator(rho, gamma));
	}

	@Override
	public boolean isElement(BigInteger value) { // TODO check if it a commitment group element
		return false;
	}

	@Override
	public GroupElement createGenerator() {
		return null;
	}

	@Override
	public GroupElement createRandomElement() {
		return null;
	}

	@Override
	public GroupElement createElement(BigInteger value) throws IllegalArgumentException, UnsupportedOperationException {
		throw new NotImplementedException("create Element not implemented");
	}

	@Override
	public boolean isKnownOrder() {
		return true;
	}

	@Override
	public GroupElement getOne() {
		return new CommitmentGroupElement(this, BigInteger.ONE);
	}

	@Override
	public Group publicClone() {
		return (CommitmentGroup) this.clone();
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
