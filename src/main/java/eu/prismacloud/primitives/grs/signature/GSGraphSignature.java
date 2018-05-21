package eu.prismacloud.primitives.grs.signature;

import eu.prismacloud.primitives.grs.commitment.ICommitment;
import eu.prismacloud.primitives.grs.keys.IGSKeyPair;
import eu.prismacloud.primitives.grs.keys.ISignerPublicKey;
import eu.prismacloud.primitives.grs.keys.SignerPublicKey;
import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.topocert.IGraph;
import java.math.BigInteger;
import java.security.SecureRandom;

public class GSGraphSignature implements IGraphSignature {

  public IGSKeyPair keyGen(int securityParam, KeyGenParameters params) {
    return null;
  }

  public ICommitment commit(IGraph graph, BigInteger rnd) {
    return null;
  }

  public IGraphSignature hiddenSign(
      ICommitment cmt, IGraph recipientGraph, IGraph signerGraph, ISignerPublicKey pk_s) {
    return null;
  }

  public ICommitment commit(IGraph graph, SecureRandom rnd) {
    return null;
  }

  public IGraphSignature hiddenSign(ICommitment cmt, ISignerPublicKey pk_s) {
    return null;
  }

  public Boolean verify(
      ISignerPublicKey pk_s, ICommitment cmt, BigInteger rTilde, IGraphSignature gsig) {
    return null;
  }

  public GSGraphSignature getGraphSignature() {
    return null;
  }

  public IGraphSignature hiddenSign(
      ICommitment cmt, IGraph recipientGraph, IGraph signerGraph, SignerPublicKey pk_s) {
    // TODO Auto-generated method stub
    return null;
  }

  public Boolean verify(
      SignerPublicKey pk_s, ICommitment cmt, BigInteger rTilde, IGraphSignature gsig) {
    // TODO Auto-generated method stub
    return null;
  }
}
