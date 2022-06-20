package uk.ac.ncl.cascade.zkpgs.commitment;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.store.URN;

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
