package uk.ac.ncl.cascade.zkpgs.context;

import java.util.List;

/**
 * Overall interface of pre-setup and post-setup proof contexts.
 *
 */
public interface IContext {
	List<String> computeChallengeContext();
	void computeWitnessContext(List<String> witnesses);
	void clearContext();
}
