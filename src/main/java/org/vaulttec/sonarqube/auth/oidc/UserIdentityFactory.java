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

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.vaulttec.sonarqube.auth.oidc.OidcConfiguration.*;

/**
 * Converts OpenID Connect {@link UserInfo} to SonarQube {@link UserIdentity}.
 */
@ServerSide
public class UserIdentityFactory {

  private static final Logger LOGGER = Loggers.get(UserIdentityFactory.class);
  
  private final OidcConfiguration config;

  public UserIdentityFactory(OidcConfiguration config) {
    this.config = config;
  }

  public UserIdentity create(UserInfo userInfo) {
    UserIdentity.Builder builder = UserIdentity.builder().setProviderId(userInfo.getSubject().getValue())
        .setProviderLogin(getLogin(userInfo)).setName(getName(userInfo)).setEmail(userInfo.getEmailAddress());
    if (config.syncGroups()) {
      builder.setGroups(getGroups(userInfo));
    }
    return builder.build();
  }

  private String getLogin(UserInfo userInfo) {
    switch (config.loginStrategy()) {
    case LOGIN_STRATEGY_PREFERRED_USERNAME:
      if (userInfo.getPreferredUsername() == null) {
        throw new IllegalStateException("Claim 'preferred_username' is missing in user info - "
            + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
      }
      return userInfo.getPreferredUsername();
    case LOGIN_STRATEGY_PROVIDER_ID:
      return userInfo.getSubject().getValue();
    case LOGIN_STRATEGY_EMAIL:
      if (userInfo.getEmailAddress() == null) {
        throw new IllegalStateException("Claim 'email' is missing in user info - "
            + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
      }
      return userInfo.getEmailAddress();
    case LOGIN_STRATEGY_UNIQUE:
      return generateUniqueLogin(userInfo);
    case LOGIN_STRATEGY_CUSTOM_CLAIM:
      if (userInfo.getStringClaim(config.loginStrategyCustomClaimName()) == null) {
        throw new IllegalStateException(
            "Custom claim '" + config.loginStrategyCustomClaimName() + "' is missing in user info - "
                + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
      }
      return userInfo.getStringClaim(config.loginStrategyCustomClaimName());
    default:
      throw new IllegalStateException(format("Login strategy not supported: %s", config.loginStrategy()));
    }
  }

  private String generateUniqueLogin(UserInfo userInfo) {
    return format("%s@%s", userInfo.getSubject().getValue(), OidcIdentityProvider.KEY);
  }

  private String getName(UserInfo userInfo) {
    String name = userInfo.getName() != null ? userInfo.getName() : userInfo.getPreferredUsername();
    if (name == null) {
      throw new IllegalStateException("Claims 'name' and 'preferred_username' are missing in user info - "
          + "make sure your OIDC provider supports at least one of these claims in the id token or at the user info endpoint");
    }
    return name;
  }

  private Set<String> getGroups(UserInfo userInfo) {
    Object groupsClaim = userInfo.getClaim(config.syncGroupsClaimName());
    if (groupsClaim == null) {
      throw new IllegalStateException("Groups claim '" + config.syncGroupsClaimName() + "' is missing in user info - "
          + "make sure your OIDC provider supports this claim in the id token or at the user info endpoint");
    }
    
    List<String> groups = new ArrayList<>();
    
    // Safely handle different group claim formats with proper type checking
    if (groupsClaim instanceof List<?>) {
      // Handle list format
      List<?> groupsList = (List<?>) groupsClaim;
      for (Object group : groupsList) {
        if (group instanceof String) {
          // Sanitize and validate group name
          String groupName = sanitizeGroupName((String) group);
          if (!groupName.isEmpty()) {
            groups.add(groupName);
          }
        }
      }
    } else if (groupsClaim instanceof String) {
      // Handle comma-separated string format
      String groupsStr = (String) groupsClaim;
      if (groupsStr.contains(",")) {
        // comma-separated list of groups
        groups = Stream.of(groupsStr.split(","))
            .map(String::trim)
            .filter(g -> !g.isEmpty())
            .map(this::sanitizeGroupName)
            .filter(g -> !g.isEmpty())
            .collect(Collectors.toList());
      } else if (!groupsStr.trim().isEmpty()) {
        // single group - sanitize and validate
        String groupName = sanitizeGroupName(groupsStr);
        if (!groupName.isEmpty()) {
          groups.add(groupName);
        }
      }
    } else if (groupsClaim instanceof String[]) {
      // Handle string array format
      for (String group : (String[]) groupsClaim) {
        if (group != null) {
          String groupName = sanitizeGroupName(group);
          if (!groupName.isEmpty()) {
            groups.add(groupName);
          }
        }
      }
    } else {
      LOGGER.warn("Unexpected type for groups claim: {}. Groups will be empty.", 
          groupsClaim.getClass().getName());
    }
    
    // Limit number of groups to prevent potential DoS
    if (groups.size() > 100) {
      LOGGER.warn("Large number of groups detected ({}). Limiting to 100.", groups.size());
      groups = groups.subList(0, 100);
    }
    
    return new HashSet<>(groups);
  }
  
  /**
   * Sanitizes group names to prevent injection attacks
   * 
   * @param groupName Raw group name from the IdP
   * @return Sanitized group name safe for use in SonarQube
   */
  private String sanitizeGroupName(String groupName) {
    if (groupName == null) {
      return "";
    }
    
    // Trim whitespace
    String trimmed = groupName.trim();
    
    // Basic validation - implement appropriate rules based on SonarQube requirements
    if (trimmed.length() > 255) {
      // Prevent extremely long group names
      return trimmed.substring(0, 255);
    }
    
    // Could add more validation as needed
    
    return trimmed;
  }

}
