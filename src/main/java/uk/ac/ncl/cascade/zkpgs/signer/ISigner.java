package uk.ac.ncl.cascade.zkpgs.signer;

import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.graph.GSEdge;
import uk.ac.ncl.cascade.zkpgs.graph.GSGraph;
import uk.ac.ncl.cascade.zkpgs.graph.GSVertex;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPrivateKey;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;

import java.math.BigInteger;

public interface ISigner extends IURNGoverner {
  SignerKeyPair keyGen(KeyGenParameters gs_params);

  GSCommitment commit(GSGraph<GSVertex, GSEdge> gsGraph, BigInteger rnd);

  GSSignature hiddenSign(
      GSCommitment cmt,
      GSVertex signerVertex,
      GSVertex recipientVertex,
      ExtendedPublicKey extendedPublicKey,
      GSGraph<GSVertex, GSEdge> gsGraph1,
      ExtendedPrivateKey extendedPrivateKey);

  void setGraph(GSGraph<GSVertex, GSEdge> signerGraph);
  /*
   * responsible for generating an appropriate key setup, certify an encoding scheme, and to sign graphs
   * In the hiddenSign() protocol the signer accepts a graph commitment from the recipient, adds an issuer-known sub-graph and
   * and completes the signature with his secret key sk_signer.
   * The signer outputs a partial graph signature, subsequently completed by the recipient.
   */

}
