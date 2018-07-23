package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.store.Base;

/** Iterator for bases */
public interface BaseIterator extends Iterable<BaseRepresentation> {
  public boolean hasNext();

  public BaseRepresentation next();
}
