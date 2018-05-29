package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.keys.IGSExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.signature.EncodingSignature;

public class GSGraphEncodingResult {

  private IGSExtendedKeyPair extendedKeyGenPair;
  private EncodingSignature signature;

  public GSGraphEncodingResult() {}

  public IGSExtendedKeyPair getExtendedKeyGenPair() {
    return extendedKeyGenPair;
  }

  public EncodingSignature getSignature() {
    return signature;
  }

  public void setSignature(EncodingSignature signature) {
    this.signature = signature;
  }
}
