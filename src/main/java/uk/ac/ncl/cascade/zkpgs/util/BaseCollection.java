package uk.ac.ncl.cascade.zkpgs.util;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.context.IContextProducer;

public interface BaseCollection extends IContextProducer, Cloneable {
	BaseIterator createIterator(BASE type);

	boolean add(BaseRepresentation base);

	boolean remove(BaseRepresentation base);
	
	BaseRepresentation get(int index);
	
	BaseRepresentation getFirst();
	
	/**
	 * Removes all exponents stored in the base collection by setting them to BigInteger.ZERO.
	 */
	void removeExponents();

	boolean contains(BaseRepresentation base);
	
	int size();
	
	BaseCollection clone();
	
	String getStringOverview();
}
