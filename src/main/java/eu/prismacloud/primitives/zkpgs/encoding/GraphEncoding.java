package eu.prismacloud.primitives.zkpgs.encoding;

import eu.prismacloud.primitives.zkpgs.GSGraphEncodingResult;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.IGraphRepresentation;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.IGSKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPrivateKey;
import eu.prismacloud.primitives.zkpgs.signature.EncodingSignature;
import eu.prismacloud.primitives.zkpgs.signature.KeyGenSignature;
import java.math.BigInteger;
import java.util.Vector;

public class GraphEncoding {

  private EncodingSignature encodingSignature;

  /* TODO public output: add number of bases to hold vertex and edge encodings */

  /* TODO public output: digitally sign the generators proving knowledge of their representation and binding them to public key pk_S -> outputs signature sigma_S,es. */

  /* TODO private output: the algorithm returns the discrete logarithms of all produced bases with respect to generator S, logS(Rk). The discrete logarithms stored securely persistently and retained for the graph signing process. */

  private ExtendedPrivateKey extendedPrivateKey;
  private ExtendedPublicKey extendedPublicKey;
  private Vector<BigInteger> discreteLogBases;

  public GraphEncoding() {}

  public EncodingSignature getEncodingSignature() {
    return encodingSignature;
  }

  public EncodingSignature signEncoding() {
    /* TODO generate encoding signature */
    return encodingSignature;
  }

  public ExtendedPrivateKey getExtendedPrivateKey() {
    return extendedPrivateKey;
  }

  public void setExtendedPrivateKey(ExtendedPrivateKey extendedPrivateKey) {
    this.extendedPrivateKey = extendedPrivateKey;
  }

  public ExtendedPublicKey getExtendedPublicKey() {
    return extendedPublicKey;
  }

  public void setExtendedPublicKey(ExtendedPublicKey extendedPublicKey) {
    this.extendedPublicKey = extendedPublicKey;
  }

  public IGraphRepresentation encode(GSGraph graph) {
    return new GraphRepresentation();
  }

  public GSGraphEncodingResult setup(
      SignerPrivateKey privateKey,
      SignerPrivateKey privateKey1,
      IGSKeyPair keyGenPair,
      KeyGenSignature signature) {
    return null;
  }
}
