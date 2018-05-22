package eu.prismacloud.primitives.grs.util;

import eu.prismacloud.primitives.grs.store.Base;

public interface BaseAggregate {
  BaseIterator createIterator();

  boolean add(Base element);

  boolean remove(Base element);
}
