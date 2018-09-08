package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;

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
}
