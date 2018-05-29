package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.store.Base;

public interface BaseAggregate {
  BaseIterator createIterator();

  boolean add(Base element);

  boolean remove(Base element);
}
