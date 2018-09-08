package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.exception.TopocertInternalError;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** */
public class BaseRepresentation implements Serializable, IContextProducer, Cloneable {

    private static final long serialVersionUID = 8542984504573091475L;

    public enum BASE {
        ALL,
        VERTEX,
        EDGE,
        BASE0,
        BASER,
        BASES;
    }

    private final int baseIndex;
    private final BASE baseType;
    private final GroupElement base;
    private BigInteger exponent;

    public BaseRepresentation(final GroupElement base, final BigInteger exponent, final int baseIndex, final BASE baseType) {

        this.base = base;
        this.exponent = exponent;
        this.baseIndex = baseIndex;
        this.baseType = baseType;
    }

    public BaseRepresentation(final GroupElement base, final int baseIndex, final BASE baseType) {

        this.base = base;
        this.baseIndex = baseIndex;
        this.baseType = baseType;
    }

    public int getBaseIndex() {
        return this.baseIndex;
    }

    public void setExponent(BigInteger exponentEncoding) {
        this.exponent = exponentEncoding;
    }

    public GroupElement getBase() {
        return this.base;
    }

    public BigInteger getExponent() {
        return this.exponent;
    }

    public BASE getBaseType() {
        return this.baseType;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(
                "eu.prismacloud.primitives.zkpgs.BaseRepresentation{");
        sb.append("baseIndex=").append(baseIndex);
        sb.append(", baseType=").append(baseType);
        sb.append(", base=").append(base);
        sb.append(", exponent=").append(exponent);
        sb.append('}');
        return sb.toString();
    }


    @Override
    public BaseRepresentation clone() {

        BaseRepresentation theClone = null;
        try {
            theClone = (BaseRepresentation) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new TopocertInternalError(e);
        }

        // No mutable members to clone
        return theClone;
    }

    @Override
    public List<String> computeChallengeContext() {
        List<String> ctxList = new ArrayList<String>();
        addToChallengeContext(ctxList);
        return ctxList;
    }

    @Override
    public void addToChallengeContext(List<String> ctxList) {
        ctxList.add(String.valueOf(this.getBase().getValue()));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if ((o == null) || (this.getClass() != o.getClass())) return false;

        BaseRepresentation that = (BaseRepresentation) o;

        if (this.getBaseIndex() != that.getBaseIndex()) return false;
        if (this.getBaseType() != that.getBaseType()) return false;
        return this.getBase().equals(that.getBase());
    }

    @Override
    public int hashCode() {
        int result = this.getBaseIndex();
        result = 31 * result + this.getBaseType().hashCode();
        result = 31 * result + this.getBase().hashCode();
        return result;
    }
}
