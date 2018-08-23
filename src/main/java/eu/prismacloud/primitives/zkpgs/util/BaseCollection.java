package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;

public interface BaseCollection extends IContextProducer {
  BaseIterator createIterator(BASE type);

  boolean add(BaseRepresentation base);

  boolean remove(BaseRepresentation base);

  int size();
}
