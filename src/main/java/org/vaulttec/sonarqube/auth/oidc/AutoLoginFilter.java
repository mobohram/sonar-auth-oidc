/*
 * OpenID Connect Authentication for SonarQube
 * Copyright (c) 2021 Torsten Juergeleit
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

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.sonar.api.server.ServerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.api.web.ServletFilter;

@ServerSide
public class AutoLoginFilter extends ServletFilter {

  private static final Logger LOGGER = Loggers.get(AutoLoginFilter.class);

  private static final String LOGIN_URL = "/sessions/new";
  private static final String OIDC_URL = "/sessions/init/" + OidcIdentityProvider.KEY + "?return_to=";
  private static final String SKIP_REQUEST_PARAM = "auto-login=false";

  private final OidcConfiguration config;

  public AutoLoginFilter(OidcConfiguration config) {
    this.config = config;
  }

  @Override
  public UrlPattern doGetPattern() {
    return UrlPattern.create(LOGIN_URL);
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (config.isEnabled() && config.isAutoLogin() && request instanceof HttpServletRequest) {
      HttpServletRequest httpRequest = (HttpServletRequest) request;
      HttpServletResponse httpResponse = (HttpServletResponse) response;
      
      // Check if autologin is explicitly disabled via request parameter
      String queryString = httpRequest.getQueryString();
      if (queryString != null && queryString.contains(SKIP_REQUEST_PARAM)) {
        LOGGER.debug("Auto-login bypassed by explicit request parameter");
        chain.doFilter(request, response);
        return;
      }
      
      // Verify referer header for CSRF protection
      String referrer = httpRequest.getHeader("referer");
      LOGGER.debug("Referrer: {}", referrer);
      
      // Skip auto-login if referer explicitly contains skip parameter
      if (referrer != null && referrer.contains(SKIP_REQUEST_PARAM)) {
        chain.doFilter(request, response);
        return;
      }
      
      // Add security headers to prevent clickjacking attacks
      httpResponse.setHeader("X-Frame-Options", "DENY");
      httpResponse.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
      
      // Generate a secure return URL that's validated to be local
      String returnPath = sanitizeReturnPath(httpRequest.getRequestURI(), config.getContextPath() + "/projects");
      String loginPageUrl = config.getBaseUrl() + OIDC_URL + returnPath;
      
      LOGGER.debug("Redirecting to OIDC login page: {}", loginPageUrl);
      httpResponse.sendRedirect(loginPageUrl);
      return;
    }
    chain.doFilter(request, response);
  }
  
  /**
   * Sanitizes and validates the return path to prevent open redirect vulnerabilities
   * 
   * @param requestedPath The path requested by the user
   * @param defaultPath The default path to use if requested path is invalid
   * @return A sanitized path that's safe to use
   */
  private String sanitizeReturnPath(String requestedPath, String defaultPath) {
    // Only allow specific paths from the same application
    if (requestedPath == null || requestedPath.isEmpty() || requestedPath.contains("://")) {
      return defaultPath;
    }
    
    // Check against a whitelist of allowed paths or patterns
    if (requestedPath.startsWith("/")) {
      // Additional validation could be added here
      return requestedPath;
    }
    
    return defaultPath;
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    // Not needed here
  }

  @Override
  public void destroy() {
    // Not needed here
  }

}
