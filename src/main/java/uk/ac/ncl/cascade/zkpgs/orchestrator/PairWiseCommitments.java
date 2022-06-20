package uk.ac.ncl.cascade.zkpgs.orchestrator;

import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;

import java.io.Serializable;

/** The type Pair wise commitments. */
public class PairWiseCommitments implements Serializable {

  private static final long serialVersionUID = -1179367424073147L;
  private GSCommitment C_i;
  private GSCommitment C_j;

  public PairWiseCommitments(GSCommitment C_i, GSCommitment C_j) {

    this.C_i = C_i;
    this.C_j = C_j;
  }

  public GSCommitment getC_i() {
    return this.C_i;
  }

  public GSCommitment getC_j() {
    return this.C_j;
  }
}
