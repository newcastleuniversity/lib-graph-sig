package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.store.Base;

/** Iterator for bases */
public interface BaseIterator {
  public boolean hasNext();

  public Base next();
}
