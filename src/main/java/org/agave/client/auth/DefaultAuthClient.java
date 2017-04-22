/**
 * 
 */
package org.agave.client.auth;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.cache.Cache;
import javax.cache.CacheException;
import javax.cache.annotation.CacheResult;

import org.agave.client.ApiException;
import org.agave.client.api.ClientsApi;
import org.agave.client.cache.LocalAgaveAuthConfig;
import org.agave.client.cache.MultitenantCacheManager;
import org.agave.client.model.Client;
import org.agave.client.model.ClientRequest;
import org.agave.client.model.ClientSubscriptionTier;
import org.agave.client.model.SingleClientResponse;
import org.agave.client.model.Tenant;

import com.github.scribejava.apis.AgaveApi;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.CustomGrantTypeOAuth20Service;
import com.github.scribejava.core.oauth.OAuth20Service;

/**
 * @author dooley
 *
 */
public class DefaultAuthClient implements AuthClient {
	
	private final static Logger logger = Logger.getLogger(DefaultAuthClient.class.getName());
	
	private Tenant tenant;
	private String clientApplicationId;
	private MultitenantCacheManager cacheManager;
	private Cache<String, LocalAgaveAuthConfig> cache;

	public DefaultAuthClient(Tenant tenant, String clientApplicationId) {
		this.tenant = tenant;
		this.clientApplicationId = clientApplicationId;
	}
	
	/**
	 * Fetches a token for the given user using the user's credentials. The token
	 * request will be made with a client created on the user's behalf and namespaced 
	 * for this tenant and client application id. That prevents unexpected invalidation 
	 * of the token by a refresh request issues from another application.
	 * 
	 * @param username
	 * @param password
	 * @return
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	public LocalAgaveAuthConfig getToken(String username, byte[] password) 
	throws ApiException, IOException, InterruptedException, ExecutionException 
	{
		OAuth2AccessToken token = null;
		LocalAgaveAuthConfig localAuthConfig = null;
		if (!getCache().containsKey(username)) {
			
			ClientsApi clientsApi = new ClientsApi();
			clientsApi.getApiClient().setBasePath(getTenant().getBaseUrl());
			clientsApi.getApiClient().setUsername(username);
			clientsApi.getApiClient().setPassword(new String(password));
			
			// define a new client application to register for the user in this namespace
			ClientRequest requestBody = new ClientRequest();
			requestBody.setName(getCacheManager().getCacheName() + "/" + username);
			requestBody.setDescription("Auto-generated client application for delegated credential caching");
			requestBody.setTier(ClientSubscriptionTier.UNLIMITED);
			
			try {
				SingleClientResponse response = clientsApi.addClient(requestBody);
				Client client = response.getResult();

				// fetch a new token with the generate client;
				token = _getToken(client, username, password);
				
				// add the client, tenant, user, and token info to a local auth config
				localAuthConfig = new LocalAgaveAuthConfig(getTenant(), client, username, token);
				
				// cache for later reuse
				getCache().put(username, localAuthConfig);
			}
			catch (ApiException e) {
				throw new IOException("Unable to create client application for user " + 
						username + " in tenant " + getTenant().getCode(), e);
			}
		}
		// we already have a valid token and client for the user in the current context,
		// check for validity of the current token and use if valid
		else {
			localAuthConfig = getCache().get(username);
			
			// if expired, walk a refresh flow
			if (localAuthConfig.getExpiresIn() <= 0) {
				try {
					token = _refreshToken(localAuthConfig);
				}
				catch (Exception e) {
					// refresh failed, try to pull a fresh one.
					// fetch a new token with the generate client;
					Client client = new Client();
					client.setKey(localAuthConfig.getApiKey());
					client.setSecret(localAuthConfig.getApiSecret());
					
					token = _getToken(client, username, password);
				}
			
				// if either call was successful, build a local auth config for caching
				localAuthConfig.setAccessToken(token.getAccessToken());
				localAuthConfig.setRefreshToken(token.getRefreshToken());
				localAuthConfig.setExpiresIn(token.getExpiresIn());
				localAuthConfig.setExpiresAt(LocalDateTime.now().plus(token.getExpiresIn().longValue(), ChronoUnit.SECONDS));
				
				getCache().put(username, localAuthConfig);
			}
		}
		
		return localAuthConfig;
	}
	
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
	throws ApiException
	{
		LocalAgaveAuthConfig localAuthConfig = getCache().get(username);
		boolean success = false;
		if (localAuthConfig != null) {
			
			try {
				final CustomGrantTypeOAuth20Service service = 
						(CustomGrantTypeOAuth20Service) new ServiceBuilder()
					        .apiKey(localAuthConfig.getApiKey())
					        .apiSecret(localAuthConfig.getApiSecret())
					        .build(AgaveApi.instance());
		
				service.revokeAccessToken(localAuthConfig.getAccessToken());
				success = true;
			}
			catch (Exception e) {
				logger.log(Level.WARNING, "Failed to revoke access token " + localAuthConfig.getAccessToken() + 
						". Token will remain valid until it expires at " + localAuthConfig.getExpiresAt().toString());
			}
		
			try {
				ClientsApi clientsApi = new ClientsApi();
				clientsApi.getApiClient().setBasePath(getTenant().getBaseUrl());
				clientsApi.getApiClient().setUsername(username);
				clientsApi.getApiClient().setPassword(new String(password));
				
				clientsApi.deleteClient(getCacheManager().getCacheName() + "/" + username);
				
				success = true;
			}
			catch (Exception e) {
				logger.log(Level.WARNING, "Failed to revoke client application " + getCacheManager().getCacheName() + 
						"/" + username + ". Token will remain valid until it expires at " + 
						localAuthConfig.getExpiresAt().toString());
			}
			
			return success;
		}
		else {
			// nothing to do here. we can't delete the token without the client info.
			success = true;
		}
		
		return success;
			
	}
	
	/**
	 * Makes the call to fetch a token from the OAuth server using the 
	 * {@link Client}, {@code username}, and {@code password}.
	 *  
	 * @param client
	 * @param username
	 * @param password
	 * @return valid {@link OAuth2AccessToken} for the {@code username}
	 * @throws ApiException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	protected OAuth2AccessToken _getToken(Client client, String username, byte[] password) 
	throws ApiException, IOException, InterruptedException, ExecutionException 
	{
		final OAuth20Service service = new ServiceBuilder()
	        .apiKey(client.getKey())
	        .apiSecret(client.getSecret())
	        .build(AgaveApi.instance());
	
		return service.getAccessTokenPasswordGrant(username, new String(password));
	}
	
	/**
	 * Makes the call to get a new auth token using the existing token in the 
	 * {@link LocalAgaveAuthConfig}.
	 *  
	 * @param localAuthConfig the current {@link LocalAgaveAuthConfig} for 
	 * the user containing client info and refresh token to carry out this action.
	 * @return valid {@link OAuth2AccessToken} for the {@code LocalAgaveAuthConfig#username}
	 * @throws ApiException
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws ExecutionException
	 */
	protected OAuth2AccessToken _refreshToken(LocalAgaveAuthConfig localAuthConfig) 
	throws ApiException, IOException, InterruptedException, ExecutionException 
	{
		final OAuth20Service service = new ServiceBuilder()
	        .apiKey(localAuthConfig.getApiKey())
	        .apiSecret(localAuthConfig.getApiSecret())
	        .build(AgaveApi.instance());
	
		return service.refreshAccessToken(localAuthConfig.getRefreshToken());
	}
	
	public MultitenantCacheManager getCacheManager() {
		if (this.cacheManager == null) {
			this.cacheManager = new MultitenantCacheManager(getTenant(), getClientApplicationId());
		}
		
		return this.cacheManager;
	}

	/**
	 * @return the cache for the 
	 */
	public Cache<String, LocalAgaveAuthConfig> getCache() 
	throws CacheException 
	{
		if (this.cache == null) {
			this.cache = cacheManager.getUserTokenCacheForClientApplication();
		}
		
		return this.cache;
	}

	/**
	 * @return the tenant
	 */
	public Tenant getTenant() {
		return tenant;
	}

	/**
	 * @param tenant the tenant to set
	 */
	public void setTenant(Tenant tenant) {
		this.tenant = tenant;
	}

	/**
	 * @return the clientApplicationId
	 */
	public String getClientApplicationId() {
		return clientApplicationId;
	}

	/**
	 * @param clientApplicationId the clientApplicationId to set
	 */
	public void setClientApplicationId(String clientApplicationId) {
		this.clientApplicationId = clientApplicationId;
	}


}
