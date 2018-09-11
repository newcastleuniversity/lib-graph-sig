package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;

/**
 * Iterator for bases
 */
public interface BaseIterator extends Iterable<BaseRepresentation> {
    boolean hasNext();

    BaseRepresentation next();

    int size();

    BaseRepresentation getBaseByIndex(int baseIndex);
}
