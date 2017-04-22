package org.agave.client.exceptions;

public class AuthConfigException extends Exception {

	private static final long serialVersionUID = 62249668447582231L;

	/**
	 * 
	 */
	public AuthConfigException() {
		super();
	}

	/**
	 * @param message
	 * @param cause
	 * @param enableSuppression
	 * @param writableStackTrace
	 */
	public AuthConfigException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public AuthConfigException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * @param message
	 */
	public AuthConfigException(String message) {
		super(message);
	}

	/**
	 * @param cause
	 */
	public AuthConfigException(Throwable cause) {
		super(cause);
	}

}
