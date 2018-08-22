package eu.prismacloud.primitives.zkpgs.orchestrator;

import java.math.BigInteger;

import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;

public class GroupSetupOrchestrator implements IProverOrchestrator {

	public GroupSetupOrchestrator(){


	}

	public void init() {}



	public void executePreChallengePhase(){
		throw new NotImplementedException("Not implemented yet.");
	}


	public BigInteger computeChallenge() {
		throw new NotImplementedException("Not implemented yet.");
	}


	public void executePostChallengePhase(BigInteger cChallenge) {
		throw new NotImplementedException("Not implemented yet.");
	}

	@Override
	public ProofSignature createProofSignature() {
		throw new NotImplementedException("Not implemented yet.");
	}

}
