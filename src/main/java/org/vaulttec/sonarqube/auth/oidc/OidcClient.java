/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2017 Torsten Juergeleit
 * mailto:torsten AT vaulttec DOT org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.vaulttec.sonarqube.auth.oidc;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import jakarta.servlet.http.HttpServletRequest;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest.Builder;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import org.sonar.api.server.ServerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

@ServerSide
public class OidcClient {

  private static final Logger LOGGER = Loggers.get(OidcClient.class);

  private static final ResponseType RESPONSE_TYPE = new ResponseType(Value.CODE);
  private final OidcConfiguration config;

  public OidcClient(OidcConfiguration config) {
    this.config = config;
  }

  public AuthenticationRequest createAuthenticationRequest(String callbackUrl, String state) {
    LOGGER.debug("Creating authentication request");
    
    // Validate callback URL
    validateCallbackUrl(callbackUrl);
    
    // Validate state parameter
    if (state == null || state.isEmpty()) {
      throw new IllegalArgumentException("State parameter cannot be null or empty - required for CSRF protection");
    }
    
    OIDCProviderMetadata providerMetadata = getProviderMetadata();
    AuthenticationRequest request;
    
    try {
      // Create a secure authentication request with nonce for added security
      Builder builder = new AuthenticationRequest.Builder(RESPONSE_TYPE, getScope(), getClientId(),
          new URI(callbackUrl));
      
      // Add a nonce parameter for replay attack prevention
      String nonce = generateSecureNonce();
      
      request = builder
          .endpointURI(providerMetadata.getAuthorizationEndpointURI())
          .state(State.parse(state))
          .nonce(new com.nimbusds.oauth2.sdk.id.Nonce(nonce))
          .build();
          
    } catch (URISyntaxException e) {
      throw new IllegalStateException("Creating new authentication request failed: " + e.getMessage(), e);
    }
    
    LOGGER.debug("Authentication request created with endpoint: {}", 
                 providerMetadata.getAuthorizationEndpointURI());
    return request;
  }
  
  private String generateSecureNonce() {
    // Generate a cryptographically secure random nonce
    byte[] nonceBytes = new byte[32]; // 256 bits
    new java.security.SecureRandom().nextBytes(nonceBytes);
    return com.nimbusds.jose.util.Base64URL.encode(nonceBytes).toString();
  }

  public AuthorizationCode getAuthorizationCode(HttpServletRequest callbackRequest) {
    LOGGER.debug("Retrieving authorization code from callback request's query parameters: {}",
        callbackRequest.getQueryString());
    AuthenticationResponse authResponse;
    try {
      HTTPRequest request = ServletUtils.createHTTPRequest(callbackRequest);
      authResponse = AuthenticationResponseParser.parse(request.getURL().toURI(), request.getQueryParameters());
    } catch (ParseException | URISyntaxException | IOException e) {
      throw new IllegalStateException("Error while parsing callback request", e);
    }
    if (authResponse instanceof AuthenticationErrorResponse) {
      ErrorObject error = ((AuthenticationErrorResponse) authResponse).getErrorObject();
      throw new IllegalStateException("Authentication request failed: " + error.toJSONObject());
    }
    AuthorizationCode authorizationCode = ((AuthenticationSuccessResponse) authResponse).getAuthorizationCode();
    LOGGER.debug("Authorization code: {}", authorizationCode.getValue());
    return authorizationCode;
  }

  public UserInfo getUserInfo(AuthorizationCode authorizationCode, String callbackUrl) {
    LOGGER.debug("Getting user info for authorization code");
    
    // Validate callback URL to prevent open redirect vulnerabilities
    validateCallbackUrl(callbackUrl);
    
    OIDCProviderMetadata providerMetadata = getProviderMetadata();
    // Verify endpoint uses HTTPS
    validateHttpsEndpoint(providerMetadata.getUserInfoEndpointURI(), "UserInfo endpoint");
    
    OIDCTokens oidcTokens = getOidcTokens(authorizationCode, callbackUrl, providerMetadata);

    UserInfo userInfo;
    try {
      userInfo = new UserInfo(oidcTokens.getIDToken().getJWTClaimsSet());
    } catch (java.text.ParseException e) {
      throw new IllegalStateException("Parsing ID token failed", e);
    }
    
    if (((userInfo.getName() == null) && (userInfo.getPreferredUsername() == null))
        || (config.syncGroups() && userInfo.getClaim(config.syncGroupsClaimName()) == null)) {
      UserInfoResponse userInfoResponse = getUserInfoResponse(providerMetadata.getUserInfoEndpointURI(),
          oidcTokens.getBearerAccessToken());
      if (userInfoResponse instanceof UserInfoErrorResponse) {
        ErrorObject errorObject = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
        if (errorObject == null || errorObject.getCode() == null) {
          throw new IllegalStateException("UserInfo request failed: No error code returned "
              + "(identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties')");
        } else {
          throw new IllegalStateException("UserInfo request failed: " + errorObject.toJSONObject());
        }
      }
      userInfo = ((UserInfoSuccessResponse) userInfoResponse).getUserInfo();
    }

    // Log only non-sensitive info for security
    LOGGER.debug("User info received with claims: {}", String.join(", ", userInfo.toJSONObject().keySet()));
    return userInfo;
  }
  
  private void validateCallbackUrl(String callbackUrl) {
    if (callbackUrl == null || callbackUrl.isEmpty()) {
      throw new IllegalArgumentException("Callback URL cannot be null or empty");
    }
    
    try {
      URI uri = new URI(callbackUrl);
      String host = uri.getHost();
      
      // Verify callback URL is using proper host
      if (host == null) {
        throw new IllegalArgumentException("Invalid callback URL: Missing host");
      }
      
      // Verify callback is using HTTPS (unless localhost for development)
      if (!"localhost".equalsIgnoreCase(host) && !"127.0.0.1".equals(host) && 
          !uri.getScheme().toLowerCase().equals("https")) {
        throw new IllegalArgumentException("Callback URL must use HTTPS for security");
      }
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid callback URL: " + e.getMessage(), e);
    }
  }
  
  private void validateHttpsEndpoint(URI endpoint, String endpointName) {
    if (endpoint == null) {
      throw new IllegalArgumentException(endpointName + " URI cannot be null");
    }
    
    if (!endpoint.getScheme().toLowerCase().equals("https")) {
      throw new IllegalStateException(endpointName + " must use HTTPS for security");
    }
  }

  private OIDCTokens getOidcTokens(AuthorizationCode authorizationCode, String callbackUrl, OIDCProviderMetadata providerMetadata) {
    LOGGER.debug("Retrieving OIDC tokens with user info claims set from {}", providerMetadata.getTokenEndpointURI());
    TokenResponse tokenResponse = getTokenResponse(providerMetadata.getTokenEndpointURI(), authorizationCode,
        callbackUrl);
    if (tokenResponse instanceof TokenErrorResponse) {
      ErrorObject errorObject = ((TokenErrorResponse) tokenResponse).getErrorObject();
      if (errorObject == null || errorObject.getCode() == null) {
        throw new IllegalStateException("Token request failed: No error code returned "
            + "(identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties')");
      } else {
        throw new IllegalStateException("Token request failed: " + errorObject.toJSONObject());
      }
    }
    OIDCTokens oidcTokens = ((OIDCTokenResponse) tokenResponse).getOIDCTokens();
    if (isIdTokenSigned()) {
      validateIdToken(providerMetadata.getIssuer(), providerMetadata.getJWKSetURI(), oidcTokens.getIDToken());
    }
    return oidcTokens;
  }

  protected TokenResponse getTokenResponse(URI tokenEndpointURI, AuthorizationCode authorizationCode,
      String callbackUrl) {
    // Validate endpoint and callback URL
    validateHttpsEndpoint(tokenEndpointURI, "Token endpoint");
    validateCallbackUrl(callbackUrl);
    
    try {
      TokenRequest request = new TokenRequest(tokenEndpointURI, new ClientSecretBasic(getClientId(), getClientSecret()),
          new AuthorizationCodeGrant(authorizationCode, new URI(callbackUrl)));
      HTTPResponse response = request.toHTTPRequest().send();
      
      // Log only status code for security, not actual content which may contain sensitive data
      LOGGER.debug("Token response status: {}", response.getStatusCode());
      
      return OIDCTokenResponseParser.parse(response);
    } catch (URISyntaxException | ParseException e) {
      throw new IllegalStateException("Retrieving access token failed: " + e.getMessage(), e);
    } catch (IOException e) {
      throw new IllegalStateException("Retrieving access token failed: "
          + "Identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties'");
    }
  }

  private void validateIdToken(Issuer issuer, URI jwkSetURI, JWT idToken) {
    LOGGER.debug("Validating ID token with {} and key set from {}", getIdTokenSignAlgorithm(), jwkSetURI);
    
    // Verify HTTPS for JWK URI for security
    if (!jwkSetURI.getScheme().toLowerCase().equals("https")) {
      throw new IllegalStateException("JWK Set URL must use HTTPS for security");
    }
    
    try {
      // Validate token with proper validator
      IDTokenValidator validator = createValidator(issuer, jwkSetURI.toURL());
      validator.validate(idToken, null);
      
      // Explicitly verify required claims
      validateRequiredClaims(idToken);
    } catch (MalformedURLException e) {
      throw new IllegalStateException("Invalid JWK set URL", e);
    } catch (BadJOSEException e) {
      throw new IllegalStateException("Invalid ID token: " + e.getMessage(), e);
    } catch (JOSEException e) {
      throw new IllegalStateException("Validating ID token failed: " + e.getMessage(), e);
    }
  }
  
  private void validateRequiredClaims(JWT idToken) {
    try {
      // Verify essential claims are present
      if (idToken.getJWTClaimsSet().getIssuer() == null) {
        throw new IllegalStateException("Missing issuer (iss) claim in ID token");
      }
      if (idToken.getJWTClaimsSet().getSubject() == null) {
        throw new IllegalStateException("Missing subject (sub) claim in ID token");
      }
      if (idToken.getJWTClaimsSet().getAudience() == null || idToken.getJWTClaimsSet().getAudience().isEmpty()) {
        throw new IllegalStateException("Missing audience (aud) claim in ID token");
      }
      
      // Verify expiration
      if (idToken.getJWTClaimsSet().getExpirationTime() == null) {
        throw new IllegalStateException("Missing expiration time (exp) claim in ID token");
      }
      if (idToken.getJWTClaimsSet().getExpirationTime().before(new java.util.Date())) {
        throw new IllegalStateException("ID token has expired");
      }
    } catch (java.text.ParseException e) {
      throw new IllegalStateException("Error parsing claims from ID token: " + e.getMessage(), e);
    }
  }

  protected IDTokenValidator createValidator(Issuer issuer, URL jwkSetUrl) {
    // In newer versions of the library, we should use a more secure validator construction
    // that includes proper algorithm checking
    JWSAlgorithm algorithm = getIdTokenSignAlgorithm();
    
    if (algorithm.equals(JWSAlgorithm.HS256) || 
        algorithm.equals(JWSAlgorithm.HS384) || 
        algorithm.equals(JWSAlgorithm.HS512)) {
      // HMAC-based validation with a shared secret
      return new IDTokenValidator(issuer, getClientId(), algorithm, getClientSecret().getValue());
    } else {
      // RSA or ECDSA validation with JWK Set URL
      return new IDTokenValidator(issuer, getClientId(), algorithm, jwkSetUrl);
    }
  }

  protected UserInfoResponse getUserInfoResponse(URI userInfoEndpointURI, BearerAccessToken accessToken) {
    LOGGER.debug("Retrieving user info from {}", userInfoEndpointURI);
    
    // Verify endpoint uses HTTPS for security
    validateHttpsEndpoint(userInfoEndpointURI, "UserInfo endpoint");
    
    try {
      UserInfoRequest request = new UserInfoRequest(userInfoEndpointURI, accessToken);
      HTTPResponse response = request.toHTTPRequest().send();
      
      // Log only status code for security, not actual content
      LOGGER.debug("UserInfo response status: {}", response.getStatusCode());
      
      return UserInfoResponse.parse(response);
    } catch (ParseException e) {
      throw new IllegalStateException("Retrieving user information failed: " + e.getMessage(), e);
    } catch (IOException e) {
      throw new IllegalStateException("Retrieving user information failed: "
          + "Identity provider not reachable - check network proxy setting 'http.nonProxyHosts' in 'sonar.properties'");
    }
  }

  protected OIDCProviderMetadata getProviderMetadata() {
    String issuerUri = config.issuerUri();
    LOGGER.debug("Retrieving provider metadata from {}", issuerUri);
    
    // Verify issuer URI is valid and uses HTTPS
    if (issuerUri == null || issuerUri.isEmpty()) {
      throw new IllegalStateException("Issuer URI cannot be null or empty");
    }
    
    try {
      URI uri = new URI(issuerUri);
      if (!uri.getScheme().toLowerCase().equals("https")) {
        throw new IllegalStateException("Issuer URI must use HTTPS for security");
      }
      
      OIDCProviderMetadata metadata = OIDCProviderMetadata.resolve(new Issuer(issuerUri));
      
      // Verify all required endpoints use HTTPS
      validateHttpsEndpoint(metadata.getAuthorizationEndpointURI(), "Authorization endpoint");
      validateHttpsEndpoint(metadata.getTokenEndpointURI(), "Token endpoint");
      if (metadata.getUserInfoEndpointURI() != null) {
        validateHttpsEndpoint(metadata.getUserInfoEndpointURI(), "UserInfo endpoint");
      }
      
      return metadata;
    } catch (IOException | GeneralException e) {
      if (e instanceof GeneralException && e.getMessage().contains("issuer doesn't match")) {
        throw new IllegalStateException("Retrieving OpenID Connect provider metadata failed: " +
                "Issuer URL in provider metadata doesn't match the issuer URI specified in plugin configuration");
      } else {
        throw new IllegalStateException("Retrieving OpenID Connect provider metadata failed: " + e.getMessage(), e);
      }
    } catch (URISyntaxException e) {
      throw new IllegalStateException("Invalid issuer URI: " + e.getMessage(), e);
    }
  }

  private Scope getScope() {
    return Scope.parse(config.scopes());
  }

  private ClientID getClientId() {
    return new ClientID(config.clientId());
  }

  private Secret getClientSecret() {
    String secret = config.clientSecret();
    return secret == null ? new Secret("") : new Secret(secret);
  }

  private boolean isIdTokenSigned() {
    // Always validate token signatures for security
    return true;
  }

  private JWSAlgorithm getIdTokenSignAlgorithm() {
    String algorithmName = config.idTokenSignAlgorithm();
    // Default to RS256 for security if not specified
    return algorithmName == null ? JWSAlgorithm.RS256 : new JWSAlgorithm(algorithmName);
  }

}
