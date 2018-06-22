package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;

/** The type Pair wise commitments. */
public class PairWiseCommitments {

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
