package eu.prismacloud.primitives.zkpgs.signature;

import eu.prismacloud.primitives.topocert.IGraph;
import eu.prismacloud.primitives.zkpgs.GraphSignature;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import java.math.BigInteger;

public interface IGraphSignature {

  /**
   * Key gen key gen pair.
   *
   * @param securityParam the security param
   * @param params the params
   * @return the key gen pair
   */
  public SignerKeyPair keyGen(int securityParam, KeyGenParameters params);

  /**
   * Commit commitment.
   *
   * @param graph the graph
   * @param rnd the rnd
   * @return the commitment
   */
  public ICommitment commit(IGraph graph, BigInteger rnd);

  /**
   * Hidden sign graph signature.
   *
   * @param cmt the cmt
   * @param pk_s the pk s
   * @return the graph signature
   */
  public IGraphSignature hiddenSign(
      ICommitment cmt, IGraph recipientGraph, IGraph signerGraph, SignerPublicKey pk_s);

  /**
   * Verify boolean.
   *
   * @param pk_s the pk s
   * @param cmt the cmt
   * @param rTilde the r tilde
   * @param gsig the gsig
   * @return the boolean
   */
  public Boolean verify(
      SignerPublicKey pk_s, ICommitment cmt, BigInteger rTilde, IGraphSignature gsig);

  GraphSignature getGraphSignature();
}
