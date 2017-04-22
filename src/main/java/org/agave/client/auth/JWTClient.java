/**
 * 
 */
package org.agave.client.auth;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;

import net.minidev.json.JSONObject;

import org.agave.client.ApiException;
import org.agave.client.Settings;
import org.agave.client.api.TenantsApi;
import org.agave.client.common.HTTPSClient;
import org.agave.client.exceptions.TenantException;
import org.agave.client.model.Tenant;
import org.apache.commons.lang.StringUtils;
import org.apache.http.util.Asserts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * @author rion1
 *
 */
public class JWTClient 
{
	private static final Logger log = LoggerFactory.getLogger(JWTClient.class);
	private static final ThreadLocal<JSONObject> threadJWTPayload = new ThreadLocal<JSONObject>();
	private static final ThreadLocal<String> threadRawJWT = new ThreadLocal<String>();
	private static final ConcurrentHashMap<String, RSAPublicKey> tenantPublicKeys = new ConcurrentHashMap<String, RSAPublicKey>();
	
	private static String getTenantPublicKeyUrl(String tenantId) throws TenantException {
		Tenant tenant = null;
		try {
			tenant = new TenantsApi().getTenantDetails(tenantId, false, null);
			
			if (tenant != null) {
				return StringUtils.removeEnd(tenant.getBaseUrl(), "/") + "/apim/v2/publickey";
			}
			else {
				throw new TenantException("No tenant found for id " + tenantId);
			}
		}
		catch (TenantException e) {
			throw e;
		}
		catch (Exception e) {
			throw new TenantException("Failed to find tenant with given id",e);
		}
		
	}
			
	private static InputStream getTenantPublicKeyInputStream(String tenantId) 
	throws IOException, FileNotFoundException
	{	
		HTTPSClient client = null;
		try {
			String publicKeyUrl = getTenantPublicKeyUrl(tenantId);
			client = new HTTPSClient(publicKeyUrl);
			log.debug("Fetching public key for tenant " + tenantId + " from " + publicKeyUrl + "...");
			String sPublicKey = client.getText();
			if (!StringUtils.isEmpty(sPublicKey)) {
				return new ByteArrayInputStream(sPublicKey.getBytes());
			}
			else {
				throw new FileNotFoundException("No public key found for tenant " + tenantId);
			}
		}
		catch (Exception e) {
			throw new IOException("Failed to fetch the public key for tenant " + tenantId, e);
		}
	}
	
	/**
	 * Fetches the {@link RSAPublicKey} for the given tenant for use in
	 * verifying the JWT signature.
	 * 
	 * @param tenantId
	 * @return
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws NoSuchProviderException 
	 * @throws Exception
	 */
	public static RSAPublicKey getTenantPublicKey(String tenantId)
	throws CertificateException, IOException, TenantException 
	{
		RSAPublicKey tenantPublicKey = tenantPublicKeys.get(tenantId);
		if (tenantPublicKey == null) 
		{	
			log.debug("Public key for tenant " + tenantId + " not found in the "
					+ "service cache. Fetching now...");
			InputStream is = null;
			try 
			{
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				
				CertificateFactory cf = CertificateFactory.getInstance("X509", "BC");
				is = getTenantPublicKeyInputStream(tenantId);
				X509Certificate certificate = (X509Certificate) cf.generateCertificate(is);
				tenantPublicKey = (RSAPublicKey)certificate.getPublicKey();
				tenantPublicKeys.put(tenantId,  tenantPublicKey);
			} 
			catch (NoSuchProviderException e) {
				throw new TenantException("Unable to load public key for tenant " + tenantId 
						+ ". No security provider found to handle the key type.", e);
			}
			catch (FileNotFoundException e) {
				throw new TenantException("Unable to locate public key for tenant " + tenantId 
						+ " at " + getTenantPublicKeyUrl(tenantId), e);
			}
			catch (IOException e) {
				throw new TenantException("Unable to fetch public key for tenant " + tenantId 
						+  " from " + getTenantPublicKeyUrl(tenantId), e);
			}
			catch (CertificateException e) {
				throw new TenantException("Unable to parse public key for tenant " + tenantId 
						+  " from " + getTenantPublicKeyUrl(tenantId), e);
			}
			catch (Exception e) {
				throw new TenantException("Unable to load public key for tenant " + tenantId 
						+ ". Unexpected error occurred.", e);
			}
			finally {
				try { is.close(); } catch (Exception e) {}
			}
		}
		
		return tenantPublicKey;
	}
	
	public JSONObject decodeJwt(String serializedJWT, RSAPublicKey pubKey) throws Exception
	{
		// register the SHA256withRSA algorithm with nimbus and Java security so
		// it will be recognized
		RSASSAVerifier.SUPPORTED_ALGORITHMS.add(
			new JWSAlgorithm("SHA256withRSA", Requirement.OPTIONAL));
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			
		// Parse the JWT into its constituent parts
		SignedJWT jwt = SignedJWT.parse(serializedJWT);

		// verify the signature 
		JWSVerifier verifier = new SHA256withRSAVerifier(pubKey);
		if (jwt.verify(verifier)) {
			return jwt.getJWTClaimsSet().toJSONObject();
		}
		else {
			throw new Exception("Bad signature on jwt");
		}
	}
	
	/**
	 * Entry method to this class. Parses the JWT and optionally validates 
	 * the signature against the known public key of the tenant auth server
	 * if {@link Settings#VERIFY_JWT_SIGNATURE} is true.
	 * @param serializedToken
	 * @param tenantId
	 * @return
	 */
	public static boolean parse(String serializedToken, String tenantId)
	{
		if (tenantId == null) return false;
		
		try 
		{
			// Create HMAC signer
			SignedJWT signedJWT = SignedJWT.parse(serializedToken);
			
			if (signedJWT != null)
			{
				RSASSAVerifier.SUPPORTED_ALGORITHMS.add(new JWSAlgorithm("SHA256withRSA", Requirement.OPTIONAL));
				
				JWSVerifier verifier = new SHA256withRSAVerifier(getTenantPublicKey(tenantId));
	            
				if (!signedJWT.verify(verifier)) {
					log.error("Invalid JWT signature.");	
					return false; 
				}
			
				ReadOnlyJWTClaimsSet claims = signedJWT.getJWTClaimsSet();
				
				Date expirationDate = claims.getExpirationTime();
				
				Asserts.notNull(expirationDate, 
						"No expiration date in the JWT header. Authentication failed.");
				
				Asserts.check(expirationDate.after(new Date()), 
						"JWT has expired. Authentication failed.");
				
				JSONObject json = claims.toJSONObject();
				json.put("rawTenantId", tenantId); // unmodified tenant id
				tenantId = StringUtils.lowerCase(tenantId);
				tenantId = StringUtils.replaceChars(tenantId, '_', '.');
				tenantId = StringUtils.replaceChars(tenantId, '-', '.');
				json.put("tenantId", tenantId);
//				log.debug(json.toJSONString());
				setCurrentJWSObject(json);
				
				setCurrentRawJWT(serializedToken);
				
				Asserts.notNull(getCurrentEndUser(), 
						"No end user specified in the JWT header. Authentication failed.");
				
				Asserts.notNull(getCurrentTenant(), 
						"No tenant specified in the JWT header. Authentication failed.");
				
				Asserts.notNull(getCurrentSubscriber(), 
						"No subscriber specified in the JWT header. Authentication failed.");
				
				return true;
			}
			
		} 
		catch (TenantException e) {
			log.error("Failed to validate JWT object.", e);
		} 
		catch (ParseException e) {
			log.error("Failed to parse JWT object. Authentication failed.", e);
		} 
		catch (Throwable e) {
			log.error("Error processing JWT header. Authentication failed.", e);
		}
		
		return false;
	}
	
	public static String getCurrentSignedJWT() {
		// TODO Auto-generated method stub
		return null;
	}
	
	public static JSONObject getCurrentJWSObject()
	{
		return threadJWTPayload.get();
	}
	
	public static void setCurrentJWSObject(JSONObject json)
	{
		threadJWTPayload.set(json);
	}
	
	public static void setCurrentRawJWT(String serializedJWT) {
		threadRawJWT.set(serializedJWT);
	}
	
	public static String getCurrentRawJWT() {
		return threadRawJWT.get();
	}
	
	public static String getCurrentApplicationId()
	{
		try {
			JSONObject claims = getCurrentJWSObject();
			return (String)claims.get("http://wso2.org/claims/applicationid");
		} catch (Exception e) {
			return null;
		}
	}
	
	public static String getCurrentSubscriber() 
	{
		try {
			JSONObject claims = getCurrentJWSObject();
			return (String)claims.get("http://wso2.org/claims/subscriber");
		} catch (Exception e) {
			return null;
		}
	}
	
	public static String getCurrentTenant()
	{
		try 
		{
			JSONObject claims = getCurrentJWSObject();
			if (claims.containsKey("tenantId") || !StringUtils.isEmpty((String)claims.get("tenantId"))) {
				return (String)claims.get("tenantId");
			}
			else
			{
				String subscriber = (String)claims.get("http://wso2.org/claims/subscriber");
				if (StringUtils.countMatches(subscriber, "@") > 0) {
					return subscriber.substring(subscriber.lastIndexOf("@") + 1);
				} else {
					return (String)claims.get("http://wso2.org/claims/enduserTenantId");
				}
			}
		} catch (Exception e) {
			return null;
		}
	}
	
	public static void setCurrentTenant(String tenantId)
	{
		JSONObject claims = getCurrentJWSObject();
		if (claims == null) {
			claims = new JSONObject();
		}
		claims.put("tenantId", tenantId);
		claims.put("http://wso2.org/claims/subscriber", tenantId);
		setCurrentJWSObject(claims);
	}
	
	public static void setCurrentEndUser(String username)
	{
		JSONObject claims = getCurrentJWSObject();
		if (claims == null) {
			claims = new JSONObject();
		}
		claims.put("http://wso2.org/claims/enduser", username);
		setCurrentJWSObject(claims);
	}

	public static String getCurrentEndUser() 
	{
		try {
			JSONObject claims = getCurrentJWSObject();
			String tenant = getCurrentTenant();
			String endUser = (String)claims.get("http://wso2.org/claims/enduser");
			endUser = StringUtils.replace(endUser, "@carbon.super", "");
			if (StringUtils.endsWith(endUser, tenant)) {
				return StringUtils.substring(endUser, 0, (-1 * tenant.length() - 1));
			} else if (endUser.contains("@")){
				return StringUtils.substringBefore(endUser, "@");
			} else if (endUser.contains("/")){
				return StringUtils.substringAfter(endUser, "/");
			} else {
				return endUser;
			}
		} catch (Exception e) {
			return null;
		}
	}
	
   public static void setCurrentBearerToken(String bearerToken)
    {
        JSONObject claims = getCurrentJWSObject();
        if (claims == null) {
            claims = new JSONObject();
        }
        claims.put("bearerToken", bearerToken);
        setCurrentJWSObject(claims);
    }
    
    public static String getCurrentBearerToken()
    {
        JSONObject claims = getCurrentJWSObject();
        if (claims == null) {
            claims = new JSONObject();
        }
        return (String)claims.get("bearerToken");
    }
	    
    public static boolean isTenantAdmin() {
		try {
			JSONObject claims = getCurrentJWSObject();
			
			String roles = (String)claims.get("http://wso2.org/claims/role");
			if (!StringUtils.isEmpty(roles)) {
				for(String role: Arrays.asList(StringUtils.split(roles, ","))) {
					if (StringUtils.endsWith(role, "-services-admin") || StringUtils.endsWith(role, "-super-admin")) {
						if (role.contains("/")) {
							role = role.substring(role.lastIndexOf("/") + 1);
						}
						if (StringUtils.startsWith(role, (String)claims.get("rawTenantId"))) {
							return true;
						}
					}
				}
				return false;
			} else {
				return false;
			}
		} catch (Exception e) {
			return false;
		}
	}
	
	public static boolean isSuperAdmin() {
		try {
			JSONObject claims = getCurrentJWSObject();
			
			String roles = (String)claims.get("http://wso2.org/claims/role");
			if (!StringUtils.isEmpty(roles)) {
				for(String role: Arrays.asList(StringUtils.split(roles, ","))) {
					if (StringUtils.endsWith(role, "-super-admin")) {
						if (role.contains("/")) {
							role = role.substring(role.lastIndexOf("/") + 1);
						}
						if (StringUtils.startsWith(role, (String)claims.get("rawTenantId"))) {
							return true;
						}
					}
				}
				return false;
			} else {
				return false;
			}
		} catch (Exception e) {
			return false;
		}
	}
	
	public static String getJwtHeaderKeyForTenant(String tenantId)
	throws TenantException
	{
		TenantsApi tenantsApi = new TenantsApi();
		Tenant tenant;
		try {
			tenant = tenantsApi.getTenantDetails(tenantId, false, null);
			
			if (tenant == null) {
				throw new TenantException("Unknown tenant id");
			} else {
				return ("x-jwt-assertion-" + StringUtils.replace(tenantId, ".", "-")).toLowerCase();
			}
		} catch (ApiException e) {
			throw new TenantException("Failed to resolve the tenant id", e);
		}
	}
	
	public static String getJwtHeaderKeyForCurrentTenant()
	throws TenantException
	{
		String tenantId = getCurrentTenant();
		
		TenantsApi tenantsApi = new TenantsApi();
		Tenant tenant;
		try {
			tenant = tenantsApi.getTenantDetails(tenantId, false, null);
			
			if (tenant == null) {
				throw new TenantException("Unknown tenant id");
			} else {
				return ("x-jwt-assertion-" + StringUtils.replace(tenantId, ".", "-")).toLowerCase();
			}
		} catch (ApiException e) {
			throw new TenantException("Failed to resolve the tenant id", e);
		}
		
		
	}
}
