package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** Base service class for the iterator. */
public class BaseCollectionImpl implements BaseCollection {
  private List<BaseRepresentation> bases;

  @Override
  public BaseIterator createIterator(BASE type) {
    return new BaseIteratorImpl(type, this.bases);
  }

  @Override
  public boolean add(BaseRepresentation base) {
    return bases.add(base);
  }

  @Override
  public boolean remove(BaseRepresentation base) {
    return bases.remove(base);
  }

  private class BaseIteratorImpl implements BaseIterator {

    private final BASE type;
    private List<BaseRepresentation> listOfBases;
    private int position;

    public BaseIteratorImpl(BASE type, List<BaseRepresentation> bases) {
      this.type = type;
      this.listOfBases = bases;
    }

    @Override
    public boolean hasNext() {
      while (position < listOfBases.size()) {
        BaseRepresentation ba = listOfBases.get(position);
        if (ba.getBaseType().equals(type) || type.equals(BASE.ALL)) {
          return true;
        } else {
          position++;
        }
      }
      return false;
    }

    @Override
    public BaseRepresentation next() {
      BaseRepresentation ba = listOfBases.get(position);
      position++;
      return ba;
    }

    @Override
    public Iterator<BaseRepresentation> iterator() {
      List<BaseRepresentation> result = new ArrayList<BaseRepresentation>();
      if (type.equals(BASE.ALL)) {
        return listOfBases.iterator();
      } else {
        for (BaseRepresentation baseRepresentation : listOfBases) {
          if (type.equals(baseRepresentation.getBaseType())) {
            result.add(baseRepresentation);
          }
        }

        return result.iterator();
      }
    }
  }

  public BaseCollectionImpl() {
    bases = new ArrayList<BaseRepresentation>();
  }

  public List<BaseRepresentation> getBases() {
    return bases;
  }

  public void setBases(List<BaseRepresentation> bases) {
    this.bases = bases;
  }

  public BaseRepresentation get(int index) {
    return bases.get(index);
  }

  public void set(int index, BaseRepresentation value) {
    bases.set(index, value);
  }

  public int size() {
    return bases.size();
  }
}
