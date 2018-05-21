package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.store.Base;
import java.util.ArrayList;
import java.util.List;

/** Base service class for the iterator. */
public class BaseService implements BaseAggregate {
  private List<Base> bases;

  @Override
  public BaseIterator createIterator() {
    return new BaseIteratorImpl(this.bases);
  }

  @Override
  public boolean add(Base element) {
    return bases.add(element);
  }

  @Override
  public boolean remove(Base element) {
    return bases.remove(element);
  }

  private class BaseIteratorImpl implements BaseIterator {
    private List<Base> listOfBases;
    private int index;

    public BaseIteratorImpl(List<Base> bases) {
      this.listOfBases = bases;
    }

    @Override
    public boolean hasNext() {
      while (index < listOfBases.size()) {
        Base ba = this.listOfBases.get(index);
        String baseId = ba.getBaseId();
        if (ba.getBaseId().equalsIgnoreCase(baseId)) {
          return true;
        } else {
          index++;
        }
      }
      return false;
    }

    @Override
    public Base next() {
      Base ba = this.listOfBases.get(index);
      index++;
      return ba;
    }
  }

  public BaseService() {
    bases = new ArrayList<Base>();
  }

  public List<Base> getBases() {
    return bases;
  }

  public void setBases(List<Base> bases) {
    this.bases = bases;
  }

  public Base get(int index) {
    return bases.get(index);
  }

  public void set(int index, Base value) {
    bases.set(index, value);
  }

  public int size() {
    return bases.size();
  }
}
