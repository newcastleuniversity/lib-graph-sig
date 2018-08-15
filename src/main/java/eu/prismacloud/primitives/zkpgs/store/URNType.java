package eu.prismacloud.primitives.zkpgs.store;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;

public enum URNType {
  TILDEE,
  TILDEV,
  TILDEVPRIME,
  TILDEM0,
  TILDEMI,
  TILDEMIJ,
  HATE,
  HATV,
  HATVPRIME,
  HATM0,
  HATMI,
  HATMIJ;
	
	public static String getSuffix(URNType t) {
		switch(t) {
		case TILDEE: return "tildee";
		case TILDEV: return "tildev";
		case TILDEVPRIME: return "tildevprime";
		case TILDEM0: return "tildem_0";
		case TILDEMI: return "tildem_i_";
		case TILDEMIJ: return "tildem_i_j_";
		case HATE: return "hate";
		case HATV: return "hatv";
		case HATVPRIME: return "hatvprime";
		case HATM0: return "hatm_0";
		case HATMI: return "hatm_i_";
		case HATMIJ: return "hatm_i_j_";
		}
		throw new RuntimeException("URNType " + t + " does not exist.");
	}
	
	public static String getClass(URNType t) {
		switch(t) {
		case TILDEE: return "witnesses.randomness";
		case TILDEV: return "witnesses.randomness";
		case TILDEVPRIME: return "witnesses.randomness";
		case TILDEM0: return "witnesses.randomness";
		case TILDEMI: return "witnesses.randomness.vertex";
		case TILDEMIJ: return "witnesses.randomness.edge";
		case HATE: return "responses";
		case HATV: return "responses";
		case HATVPRIME: return "responses";
		case HATM0: return "responses";
		case HATMI: return "responses.vertex";
		case HATMIJ: return "responses.edge";
		}
		throw new RuntimeException("URNType " + t + " does not exist.");
	}
	
	public static boolean isEnumerable(URNType t) {
		switch(t) {
		case TILDEMI: return true;
		case TILDEMIJ: return true;
		case HATMI: return true;
		case HATMIJ: return true;
		default: return false;
		}
	}
}
