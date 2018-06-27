package eu.prismacloud.primitives.zkpgs.prover;

/** */
public class ProverFactory {
  public enum ProverType {
    CommitmentProver,
    GroupSetupProver,
    CorectnessProver,
    PossessionProver,
    PairWiseDifferenceProver
  }

  public static IProver newProver(ProverType type) {
    if (type == ProverType.GroupSetupProver) {
      return new GroupSetupProver();
    } else if (type == ProverType.CommitmentProver) {
      return new CommitmentProver();
    } else if (type == ProverType.CorectnessProver) {
      return new CorrectnessProver();
    } else if (type == ProverType.PossessionProver) {
      return new GSPossessionProver();
    } else if (type == ProverType.PairWiseDifferenceProver) {
      return new PairWiseDifferenceProver();
    } else {
      return null;
    }
  }
}
