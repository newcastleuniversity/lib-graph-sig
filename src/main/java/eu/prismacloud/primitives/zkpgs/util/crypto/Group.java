package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.io.Serializable;
import java.math.BigInteger;

/** High-level abstraction of a number-theoretic group. */
public abstract class Group implements Serializable {

	private static final long serialVersionUID = 7933357117240792496L;

	/**
	 * Returns the group order, if it is known or efficiently computable.
	 * 
	 * Throws a UnsupportedOperationException() if the group order cannot be derived.
	 * 
	 * @throws UnsupportedOperationException if obtaining the group order is intractable. 
	 * 
	 * @return BigInteger group order \phi(getModulus()).
	 */
	public abstract BigInteger getOrder() throws UnsupportedOperationException;

	/**
	 * Returns a generator of the group.
	 * 
	 * The contract of this method is that first call of this method may be 
	 * computationally expensive if a generator needs to be computed first.
	 * 
	 * @return BigInteger group generator
	 */
	public abstract GroupElement getGenerator();

	/**
	 * Returns the modulus of the group.
	 * 
	 * @return BigInteger modulus
	 */
	public abstract BigInteger getModulus();

	/**
	 * Evaluates if a given BigInteger value is a member of this group.
	 * 
	 * Note that for some group setups it is intractable to decide whether a BigInteger is
	 * a group element. Then this method will throw an exception.
	 * 
	 * @param value
	 * @return
	 */
	public abstract boolean isElement(BigInteger value) throws UnsupportedOperationException;

	/**
	 * Computes a generator for this group.
	 * 
	 * This method may be either computationally expensive or intractable depending on the group setup.
	 * For that reason, generators will often be generated at setup time.
	 * 
	 * @return a BigInteger group generator
	 */
	public abstract GroupElement createGenerator();

	/**
	 * Generates a uniformly chosen random element of the group.
	 * 
	 * @return GroupElement
	 */
	public abstract GroupElement createRandomElement();

	/**
	 * This method seeks to create an group element from the given value.
	 * The method may throw an IllegalArgumentException() if the value is not a compatible group element.
	 * It throws an UnsupportedOperationException() if it is intractable to decide if the given BigInteger 
	 * is a group element or not.
	 * 
	 * @throws IllegalArgumentException when the argument BigInteger is not a valid group element
	 * @throws UnknownOperationException when it is intractable to decide whether the group element 
	 *    is valid or not.
	 * 
	 * @param value BigInteger candidate for a group element.
	 * 
	 * @return
	 */
	public abstract GroupElement createElement(BigInteger value) throws IllegalArgumentException, UnsupportedOperationException;

	/**
	 * States whether this group is a known-order group.
	 * 
	 * @return if the order is known or efficiently derivable.
	 */
	public abstract boolean isKnownOrder();
	
	/**
	 * Returns the identity element with respect to multiplication, one, of this particular group.
	 * 
	 * @return the multiplicative identity.
	 */
	public abstract GroupElement getOne();
	
}
