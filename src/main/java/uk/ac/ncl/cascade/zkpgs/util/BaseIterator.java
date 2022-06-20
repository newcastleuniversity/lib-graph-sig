package uk.ac.ncl.cascade.zkpgs.util;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;

/**
 * Iterator for bases
 */
public interface BaseIterator extends Iterable<BaseRepresentation> {
    boolean hasNext();

    BaseRepresentation next();

    int size();

    BaseRepresentation getBaseByIndex(int baseIndex);
}
