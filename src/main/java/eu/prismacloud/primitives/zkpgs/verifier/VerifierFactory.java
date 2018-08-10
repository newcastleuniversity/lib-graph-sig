package eu.prismacloud.primitives.zkpgs.verifier;

/** */
public class VerifierFactory {
  public enum VerifierType {
    CommitmentVerifier,
    GroupSetupVerifier,
    CorrectnessVerifier,
    PossessionVerifier,
    PairWiseDifferenceVerifier
  }

  public static IVerifier newVerifier(VerifierType type) {
    if (type == VerifierType.GroupSetupVerifier) {
      return new GroupSetupVerifier();
    } else if (type == VerifierType.CommitmentVerifier) {
      return new CommitmentVerifier();
    } else if (type == VerifierType.CorrectnessVerifier) {
      return new CorrectnessVerifier();
    } else if (type == VerifierType.PossessionVerifier) {
      return new PossessionVerifier();
    } else if (type == VerifierType.PairWiseDifferenceVerifier) {
      return new PairWiseDifferenceVerifier();
    } else {
      return null;
    }
  }
}
