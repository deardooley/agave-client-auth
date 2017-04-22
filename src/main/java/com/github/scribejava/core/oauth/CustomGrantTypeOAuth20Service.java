/**
 * 
 */
package com.github.scribejava.core.oauth;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import com.github.scribejava.apis.AgaveApi;
import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthAsyncRequestCallback;
import com.github.scribejava.core.model.OAuthConfig;
import com.github.scribejava.core.model.OAuthConstants;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.services.Base64Encoder;

/**
 * Extends the standard OAuth20Service with the impersonation grant type
 * used by the Agave Platform.
 * @author dooley
 *
 */
public class CustomGrantTypeOAuth20Service extends OAuth20Service {

	private final String TOKEN_USERNAME = "token_username";
	private final String ADMIN_PASSWORD_GRANT_TYPE = "admin_password";
	
	/**
	 * @param api
	 * @param config
	 */
	public CustomGrantTypeOAuth20Service(DefaultApi20 api, OAuthConfig config) {
		super(api, config);
	}
	
	public final OAuth2AccessToken getAccessTokenAdminPasswordGrant(String serviceUname, String servicePassword, String tokenUsername)
            throws IOException, InterruptedException, ExecutionException {
        final OAuthRequest request = createAccessTokenAdminPasswordGrantRequest(serviceUname, servicePassword, tokenUsername);

        return sendAccessTokenRequestSync(request);
    }

	public final Future<OAuth2AccessToken> getAccessTokenAdminPasswordGrantAsync(String serviceUname, String servicePassword, String uname) {
        return getAccessTokenAdminPasswordGrantAsync(serviceUname, servicePassword, uname, null);
    }

    /**
     * Request Access Token Impersonation Grant async version
     *
     * @param serviceUname Service user name
     * @param servicePassword Service user password
     * @param uname Username of the impersonated user
     * @param callback Optional callback
     * @return Future
     */
    public final Future<OAuth2AccessToken> getAccessTokenAdminPasswordGrantAsync(String serviceUname, String servicePassword, 
    		String uname, OAuthAsyncRequestCallback<OAuth2AccessToken> callback) {
        final OAuthRequest request = createAccessTokenAdminPasswordGrantRequest(serviceUname, servicePassword, uname);

        return sendAccessTokenRequestAsync(request, callback);
    }

    protected OAuthRequest createAccessTokenAdminPasswordGrantRequest(String serviceUname, String servicePassword, String uname) {
        final OAuthRequest request = new OAuthRequest(super.getApi().getAccessTokenVerb(), super.getApi().getAccessTokenEndpoint());
        final OAuthConfig config = getConfig();
        request.addParameter(OAuthConstants.USERNAME, serviceUname);
        request.addParameter(OAuthConstants.PASSWORD, servicePassword);
        request.addParameter(TOKEN_USERNAME, uname);

        final String scope = config.getScope();
        if (scope != null) {
            request.addParameter(OAuthConstants.SCOPE, scope);
        }

        request.addParameter(OAuthConstants.GRANT_TYPE, ADMIN_PASSWORD_GRANT_TYPE);

        final String apiKey = config.getApiKey();
        final String apiSecret = config.getApiSecret();
        if (apiKey != null && apiSecret != null) {
            request.addHeader(OAuthConstants.HEADER,
                    OAuthConstants.BASIC + ' '
                    + Base64Encoder.getInstance()
                    .encode(String.format("%s:%s", apiKey, apiSecret).getBytes(Charset.forName("UTF-8"))));
        }

        return request;
    }
    
    /**
     * Immediately invalidates the access token and renders the refresh token useless.
     * @param accessToken
     * @return
     */
    public void revokeAccessToken(String accessToken) {
        final OAuthRequest request = new OAuthRequest(Verb.POST, ((AgaveApi)super.getApi()).getTokenRevocationEndpoint());
        final OAuthConfig config = getConfig();
        request.addParameter(OAuthConstants.TOKEN, accessToken);
        
        final String apiKey = config.getApiKey();
        final String apiSecret = config.getApiSecret();
        if (apiKey != null && apiSecret != null) {
            request.addHeader(OAuthConstants.HEADER,
                    OAuthConstants.BASIC + ' '
                    + Base64Encoder.getInstance()
                    .encode(String.format("%s:%s", apiKey, apiSecret).getBytes(Charset.forName("UTF-8"))));
        }

        sendTokenRevocationRequestAsync(request);
    }
    
  //protected to facilitate mocking
    protected Future<String> sendTokenRevocationRequestAsync(OAuthRequest request) {
        return sendTokenRevocationRequestAsync(request, null);
    }

    //protected to facilitate mocking
    protected Future<String> sendTokenRevocationRequestAsync(OAuthRequest request,
            OAuthAsyncRequestCallback<String> callback) {

        return execute(request, callback, new OAuthRequest.ResponseConverter<String>() {
            @Override
            public String convert(Response response) throws IOException {
            	return response.getBody();
            }
        });
    }
}
