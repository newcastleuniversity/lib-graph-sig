package eu.prismacloud.primitives.zkpgs.commitment;

import java.math.BigInteger;

public interface ICommitment {
  BigInteger getCommitment();

  //    BigInteger getCapR();
  //
  //    BigInteger getCapS();
  //
  //    BigInteger getN();
  //
  //    int getNumBases();
}