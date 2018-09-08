package eu.prismacloud.primitives.topocert;

public class TopocertErrorCodes {
	public static final int EX_USAGE = 2;	/* command line usage error */
	public static final int EX_DATAERR = 3;	/* data format error */
	public static final int EX_NOINPUT = 66;	/* cannot open input */
	public static final int EX_ENCERR = 77;	/* encoding setup error */
	public static final int EX_NOHOST = 68;	/* host name unknown */
	public static final int EX_UNAVAILABLE = 69;	/* service unavailable */
	public static final int EX_SOFTWARE	= -1;	/* internal software error */
	public static final int EX_STATE = -2;	/* illegal state exception */
	public static final int EX_CRITERR = -3;	/* system error (e.g. unable to clone) */
	public static final int EX_CRITFILE =	-4;	/* critical file missing */
	public static final int EX_CANTCREAT = 73;/* can't create (user) output file */
	public static final int EX_IOERR = 74; /* input/output error */

	public static final int EX_PROTOCOL	= 76;	/* remote error in protocol */
	public static final int EX_VERIFY = 77; /* ZKP Verification error */
	
	public static final int EX_CONFIG = 78;	/* configuration error */
}
