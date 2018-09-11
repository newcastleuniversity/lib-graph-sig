package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

class BaseIteratorImpl implements BaseIterator {

    private final BASE type;
    private final List<BaseRepresentation> listOfBases;
    private List<BaseRepresentation> filteredBases;
    private int position;

    public BaseIteratorImpl(final BASE type, final List<BaseRepresentation> bases) {
        this.type = type;
        this.listOfBases = bases;
        this.filteredBases = new ArrayList<BaseRepresentation>();
    }

    @Override
    // TODO hasNext() Does not account for null exponents.
    public boolean hasNext() {
        while (position < listOfBases.size()) {
            BaseRepresentation ba = listOfBases.get(position);
            if (ba.getBaseType().equals(type) || type.equals(BASE.ALL) || (ba.getExponent() == null)) {
                return true;
            } else {
                position++;
            }
        }
        return false;
    }

    public int size() {
        if (filteredBases.size() == 0) {
            return filter().size();
        } else {
            return filteredBases.size();
        }
    }

    @Override
    public BaseRepresentation next() {
        BaseRepresentation ba = listOfBases.get(position);
        position++;
        return ba;
    }

    @Override
    public Iterator<BaseRepresentation> iterator() {
        filter();
        return filteredBases.iterator();
    }

    public BaseRepresentation getBaseByIndex(int baseIndex) {
        filter();

        for (BaseRepresentation filteredBase : filteredBases) {
            if (baseIndex == filteredBase.getBaseIndex()) {
                return filteredBase;
            }
        }

        return null;

    }

    private List<BaseRepresentation> filter() {

        if (type.equals(BASE.ALL)) {
            for (BaseRepresentation baseRepresentation : listOfBases) {
                if (baseRepresentation.getExponent() != null) {
                    filteredBases.add(baseRepresentation);
                }
            }
        } else {
            for (BaseRepresentation baseRepresentation : listOfBases) {
                if (type.equals(baseRepresentation.getBaseType())
                        && baseRepresentation.getExponent() != null) {
                    filteredBases.add(baseRepresentation);
                }
            }
        }
        return filteredBases;
    }
}
