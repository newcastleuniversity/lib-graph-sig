package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.Vector;

/** */
public class GroupSetupProver implements IProver {

  private BigInteger r_Z;
  private BigInteger r;
  private BigInteger r_0;
  private BigInteger tilde_r_Z;
  private BigInteger tilde_r;
  private BigInteger tilde_r_0;
  private BigInteger tilde_Z;
  private BigInteger tilde_R;
  private BigInteger tilde_R_0;
  private BigInteger hat_r_Z;
  private BigInteger hat_r;
  private BigInteger hat_r_0;
  private Iterator<GSVertex> gsVertexIterator;
  private Iterator<GSEdge> gsEdgeIterator;
  private Vector<GSVertex> gsVertices;
  private Vector<GSEdge> gsEdges;
  private int bitLength;
  private BigInteger S;
  private BigInteger N;
  private BigInteger Z;
  private BigInteger cChallenge;
  private Vector<BigInteger> challengeList = new Vector<BigInteger>();
  private KeyGenParameters keyGenParameters;

  public GroupSetupProver(
      final BigInteger S,
      final BigInteger N,
      final BigInteger Z,
      final KeyGenParameters keyGenParameters) {
    this.S = S;
    this.N = N;
    this.Z = Z;
    this.keyGenParameters = keyGenParameters;
  }

  @Override
  public void createWitnessRandomness() {
    bitLength = computeBitlength();
    tilde_r_Z = CryptoUtilsFacade.computeRandomNumber(bitLength);
    tilde_r = CryptoUtilsFacade.computeRandomNumber(bitLength);
    tilde_r_0 = CryptoUtilsFacade.computeRandomNumber(bitLength);
    /** TODO add randomness for vertex and edge iterators */
  }

  @Override
  public void computeWitness() {
    tilde_Z = S.modPow(tilde_r_Z, N);
    tilde_R = S.modPow(tilde_r, N);
    tilde_R_0 = S.modPow(tilde_R_0, N);
    /** TODO compute witnesses for vertex and edge iterators */
  }

  @Override
  public void computeChallenge() {
    challengeList = populateChallengeList();
    cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  @Override
  public void computeResponses() {

    hat_r_Z = tilde_r_Z.add(cChallenge.multiply(r_Z));
    hat_r = tilde_r.add(cChallenge.multiply(r));
    hat_r_0 = tilde_R_0.add(cChallenge.multiply(r_0));
    /** TODO compute responses for vertex and edge iterators */
  }

  private int computeBitlength() {
    return keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H();
  }

  private Vector<BigInteger> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    challengeList.add(N);
    challengeList.add(S);
    challengeList.add(Z);
    // challengeList.add(R);
    // challengeList.add(R_0);
    /** TODO iterate over bases for vertices and edges */
    // challengeList.add(R_i);
    // challengeList.add(R_j);
    challengeList.add(tilde_Z);
    challengeList.add(tilde_R);
    challengeList.add(tilde_R_0);
    /** TODO iterate over bases for vertices and edges */
    // challengeList.add(tilde_R_i);
    // challengeList.add(tilde_R_j);
    return challengeList;
  }
}
