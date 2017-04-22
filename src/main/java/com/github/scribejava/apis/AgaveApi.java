/**
 * 
 */
package com.github.scribejava.apis;

import org.agave.client.model.Tenant;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.extractors.OAuth2AccessTokenExtractor;
import com.github.scribejava.core.extractors.TokenExtractor;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConfig;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.CustomGrantTypeOAuth20Service;
import com.github.scribejava.core.oauth.OAuth20Service;

/**
 * @author dooley
 *
 */
public class AgaveApi extends DefaultApi20 {
	
	private String baseUrl = null;
	
	public AgaveApi() {
		this.baseUrl = "https://public.agaveapi.co";
	}
	
	public AgaveApi(Tenant tenant) {
		this.baseUrl = tenant.getBaseUrl();
	}

	public AgaveApi(String baseUrl) {
		this.baseUrl = baseUrl;
	}

	private static class InstanceHolder {
		private static final AgaveApi INSTANCE = new AgaveApi();
	}

	public static AgaveApi instance() {
		return InstanceHolder.INSTANCE;
	}

	@Override
	public Verb getAccessTokenVerb() {
		return Verb.POST;
	}

	@Override
	public String getAccessTokenEndpoint() {
		return this.baseUrl + "/token";
	}
	
	public String getTokenRevocationEndpoint() {
		return this.baseUrl + "/revoke";
	}

	@Override
	protected String getAuthorizationBaseUrl() {
		return this.baseUrl + "/authorize";
	}

	@Override
	public TokenExtractor<OAuth2AccessToken> getAccessTokenExtractor() {
		return OAuth2AccessTokenExtractor.instance();
	}
	
	@Override
    public OAuth20Service createService(OAuthConfig config) {
        return new CustomGrantTypeOAuth20Service(this, config);
    }
}
