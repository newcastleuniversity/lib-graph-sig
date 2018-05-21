package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.store.Base;

/** Iterator for bases */
public interface BaseIterator {
  public boolean hasNext();

  public Base next();
}
