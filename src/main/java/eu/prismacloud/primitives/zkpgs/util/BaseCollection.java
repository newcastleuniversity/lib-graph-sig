package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;

public interface BaseCollection {
  BaseIterator createIterator(BASE type);

  boolean add(BaseRepresentation base);

  boolean remove(BaseRepresentation base);

  int size();
}
