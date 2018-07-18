package eu.prismacloud.primitives.zkpgs.context;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Represents the public knowledge before the proof */
public class GSContext {
  private static final List<String> ctxList = new ArrayList<String>();

  private GSContext() {}

  public static List<String> computeChallengeContext(
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    SignerPublicKey publicKey = extendedPublicKey.getPublicKey();
    Map<URN, BaseRepresentation> bases = extendedPublicKey.getBases();
    Map<URN, BigInteger> labels = extendedPublicKey.getLabelRepresentatives();

    addKeyGenParameters(keyGenParameters);

    ctxList.add(String.valueOf(publicKey.getModN()));
    ctxList.add(String.valueOf(publicKey.getBaseS().getValue()));
    ctxList.add(String.valueOf(publicKey.getBaseZ().getValue()));
    ctxList.add(String.valueOf(publicKey.getBaseR_0().getValue()));

    /** TODO add context for bases and labels */
    //    for (BaseRepresentation base : bases.values()) {
    //      ctxList.add(String.valueOf(base.getBase().getValue()));
    //    }
    //
    //    for (BigInteger label : labels.values()) {
    //      ctxList.add(String.valueOf(label));
    //    }

    addGraphEncodingParameters(graphEncodingParameters);

    return ctxList;
  }

  public static void computeWitnessContext(List<String> witnesses) {
    for (String element : witnesses) {
      ctxList.add(element);
    }
  }

  public static void clearContext() {
    ctxList.clear();
  }

  private static void addKeyGenParameters(KeyGenParameters keyGenParameters) {
    ctxList.add(String.valueOf(keyGenParameters.getL_n()));
    ctxList.add(String.valueOf(keyGenParameters.getL_gamma()));
    ctxList.add(String.valueOf(keyGenParameters.getL_rho()));
    ctxList.add(String.valueOf(keyGenParameters.getL_m()));
    ctxList.add(String.valueOf(keyGenParameters.getL_res()));
    ctxList.add(String.valueOf(keyGenParameters.getL_e()));
    ctxList.add(String.valueOf(keyGenParameters.getL_prime_e()));
    ctxList.add(String.valueOf(keyGenParameters.getL_v()));
    ctxList.add(String.valueOf(keyGenParameters.getL_statzk()));
    ctxList.add(String.valueOf(keyGenParameters.getL_H()));
    ctxList.add(String.valueOf(keyGenParameters.getL_r()));
    ctxList.add(String.valueOf(keyGenParameters.getL_pt()));
  }

  private static void addGraphEncodingParameters(GraphEncodingParameters graphEncodingParameters) {
    ctxList.add(String.valueOf(graphEncodingParameters.getL_V()));
    ctxList.add(String.valueOf(graphEncodingParameters.getlPrime_V()));
    ctxList.add(String.valueOf(graphEncodingParameters.getL_E()));
    ctxList.add(String.valueOf(graphEncodingParameters.getL_L()));
    ctxList.add(String.valueOf(graphEncodingParameters.getlPrime_L()));
  }
}
