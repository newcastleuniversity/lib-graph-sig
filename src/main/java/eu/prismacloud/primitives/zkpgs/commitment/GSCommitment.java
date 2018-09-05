package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSCommitment implements Serializable {

    private static final long serialVersionUID = -6253701534775989050L;
    private final GroupElement commitmentValue;
    private final Map<URN, GroupElement> basesR;
    private final Map<URN, BigInteger> exponents;
    private final BigInteger randomness;

    private GSCommitment(final Map<URN, GroupElement> basesRMap,
                         final Map<URN, BigInteger> exponentMap,
                         final BigInteger rnd,
                         final GroupElement commitment) {

        Assert.notNull(commitment, "commitment cannot be null");

        this.basesR = basesRMap;
        this.exponents = exponentMap;
        this.randomness = rnd;
        this.commitmentValue = commitment;
    }


    public static GSCommitment createCommitment(GroupElement baseR, BigInteger m, BigInteger rnd, GroupElement baseS, BigInteger modN) {
        Assert.notNull(m, "message m cannot be null");
        Assert.notNull(baseR, "baseR cannot be null");
        Assert.notNull(rnd, "randomness cannot be null");
        Assert.notNull(modN, "modulus N cannot be null");

        GroupElement commimentValue = baseR.modPow(m).multiply(baseS.modPow(rnd));

        Map<URN, BigInteger> exponentMap = new HashMap<URN, BigInteger>();
        exponentMap.put(URN.createZkpgsURN("commitment.exponent.m"), m);

        Map<URN, GroupElement> basesRMap = new HashMap<URN, GroupElement>();
        basesRMap.put(URN.createZkpgsURN("commitment.base.R"), baseR);

        return new GSCommitment(basesRMap, exponentMap, rnd, commimentValue);
    }


    public static GSCommitment createCommitment(BigInteger m, GroupElement baseR, ExtendedPublicKey epk) {
        Assert.notNull(m, "message m cannot be null");
        Assert.notNull(baseR, "baseR cannot be null");
        Assert.notNull(epk, "Extended public key cannot be null");

        KeyGenParameters keyGenParameters = epk.getPublicKey().getKeyGenParameters();

        // GroupElement message = baseR.modPow(m);

        // Establishing blinding
        BigInteger r = CryptoUtilsFacade.computeRandomNumberMinusPlus(
                keyGenParameters.getL_n() + keyGenParameters.getL_statzk());
        // GroupElement blinding = epk.getPublicKey().getBaseS().modPow(r);
        BigInteger modN = epk.getPublicKey().getModN();
        Assert.notNull(modN, "modulus N cannot be null");

        GroupElement baseS = epk.getPublicKey().getBaseS();
        Assert.notNull(baseS, "base S cannot be null");

        // GroupElement commitmentValue = message.multiply(blinding);
        GroupElement commimentValue = baseR.modPow(m).multiply(baseS.modPow(r));


        Map<URN, BigInteger> exponentMap = new HashMap<URN, BigInteger>();
        exponentMap.put(URN.createZkpgsURN("commitment.exponent.m"), m);

        Map<URN, GroupElement> basesRMap = new HashMap<URN, GroupElement>();
        basesRMap.put(URN.createZkpgsURN("commitment.base.R"), baseR);

        return new GSCommitment(basesRMap, exponentMap, r, commimentValue);
    }

    public static GSCommitment createCommitment(Map<URN, GroupElement> basesR,
                                                Map<URN, BigInteger> exponents, BigInteger rnd,
                                                ExtendedPublicKey epk) {

        Assert.notNull(basesR, "base R cannot be null");
        Assert.notNull(exponents, "exponents cannot be null");
        Assert.notNull(rnd, "randomness cannot be null");
        Assert.notNull(epk, "Extended public key cannot be null");
        BigInteger modN = epk.getPublicKey().getModN();
        Assert.notNull(modN, "modulus N cannot be null");

        GroupElement baseS = epk.getPublicKey().getBaseS();
        Assert.notNull(baseS, "base S cannot be null");

        Group qrGroup = epk.getPublicKey().getQRGroup();
        BigInteger result = CryptoUtilsFacade.computeMultiBaseExpMap(basesR, exponents, modN);
        GroupElement commitmentValue = new QRElement(qrGroup, result).multiply(baseS.modPow(rnd));

        return new GSCommitment(basesR, exponents, rnd, commitmentValue);
    }


    public GroupElement getCommitmentValue() {
        return commitmentValue;
    }

    public Map<URN, GroupElement> getBasesR() {
        return basesR;
    }

    public Map<URN, BigInteger> getExponents() {
        return exponents;
    }

    public BigInteger getRandomness() {
        return randomness;
    }

}
