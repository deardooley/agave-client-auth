package org.agave.client.auth;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

import org.agave.client.ApiException;
import org.agave.client.cache.LocalAgaveAuthConfig;
import org.agave.client.model.Client;

import com.github.scribejava.core.model.OAuth2AccessToken;

public interface AuthClient {
	
	/**
	 * Fetch a new token from the Agave OAuth server with the user credentials
	 * @param username
	 * @param password
	 * @return
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	public abstract LocalAgaveAuthConfig getToken(String username, byte[] password) 
			throws ApiException, IOException, InterruptedException, ExecutionException;
	
	/**
	 * Makes the call to fetch a token from the OAuth server using the 
	 * {@link Client}, {@code username}, and {@code password}.
	 *  
	 * @param username
	 * @param password
	 * @return valid {@link OAuth2AccessToken} for the {@code username}
	 * @throws ApiException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	public boolean revokeToken(String username, byte[] password) 
	throws ApiException;
}
