package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.IGSKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import java.math.BigInteger;

public interface ISigner {
  IGSKeyPair keyGen(KeyGenParameters gs_params);

  GSCommitment commit(GSGraph gsGraph, BigInteger rnd);

  GSGraphSignature hiddenSign(
      GSCommitment cmt,
      GSVertex signerVertex,
      GSVertex recipientVertex,
      ExtendedPublicKey extendedPublicKey,
      GSGraph gsGraph1,
      ExtendedPrivateKey extendedPrivateKey);

  void setGraph(GSGraph signerGraph);
  /*
   * responsible for generating an appropriate key setup, certify an encoding scheme, and to sign graphs
   * In the hiddenSign() protocol the signer accepts a graph commitment from the recipient, adds an issuer-known sub-graph and
   * and completes the signature with his secret key sk_signer.
   * The signer outputs a partial graph signature, subsequently completed by the recipient.
   */

}
