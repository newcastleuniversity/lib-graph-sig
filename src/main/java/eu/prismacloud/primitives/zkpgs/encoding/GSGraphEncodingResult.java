package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.signature.EncodingSignature;

public class GSGraphEncodingResult {

  private ExtendedKeyPair extendedKeyGenPair;
  private EncodingSignature signature;

  public GSGraphEncodingResult() {}

  public ExtendedKeyPair getExtendedKeyGenPair() {
    return extendedKeyGenPair;
  }

  public EncodingSignature getSignature() {
    return signature;
  }

  public void setSignature(EncodingSignature signature) {
    this.signature = signature;
  }
}
