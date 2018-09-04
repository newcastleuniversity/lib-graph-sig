package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;

public interface BaseCollection extends IContextProducer, Cloneable {
	BaseIterator createIterator(BASE type);

	boolean add(BaseRepresentation base);

	boolean remove(BaseRepresentation base);
	
	/**
	 * Removes all exponents stored in the base collection by setting them to null.
	 */
	void removeExponents();

	int size();
	
	BaseCollection clone();
}
