package eu.prismacloud.primitives.zkpgs.verifier;

public interface IVerifier {
  void checkLengths();

  void computeHatValues();

  void computeVerificationChallenge();

  void verifyChallenge();
}
