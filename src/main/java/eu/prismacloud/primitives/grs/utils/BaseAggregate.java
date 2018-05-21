package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.store.Base;

public interface BaseAggregate {
  BaseIterator createIterator();

  boolean add(Base element);

  boolean remove(Base element);
}
