package eu.prismacloud.primitives.zkpgs.commitment;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.store.URN;

import java.math.BigInteger;
import java.util.Map;

public interface ICommitment {
  BigInteger getCommitment();

  Map<URN, BaseRepresentation> getVertices();

  Map<URN, BaseRepresentation> getEdges();

  //    BigInteger getCapR();
  //
  //    BigInteger getCapS();
  //
  //    BigInteger getModN();
  //
  //    int getNumBases();
}
