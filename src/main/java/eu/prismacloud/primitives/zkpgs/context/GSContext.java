package eu.prismacloud.primitives.zkpgs.context;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupN;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/** Represents the public knowledge before the proof */
public class GSContext {

  private KeyGenParameters keyGenParameters;
  private List<BigInteger> ctxList = new ArrayList<BigInteger>();
  private QRGroupN groupN;
  private ExtendedPublicKey extendedPublicKey;

  public GSContext() {}

  public List<BigInteger> computeGSContext() {
    addKeyGenParameters();
    ctxList.add(groupN.getModulus());
    ctxList.add(groupN.getGenerator().getValue());

    return ctxList;
  }

  private void addKeyGenParameters() {
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_n()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_gamma()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_rho()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_m()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_res()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_e()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_prime_e()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_v()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_statzk()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_H()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_r()));
    ctxList.add(BigInteger.valueOf(keyGenParameters.getL_pt()));
  }
}
