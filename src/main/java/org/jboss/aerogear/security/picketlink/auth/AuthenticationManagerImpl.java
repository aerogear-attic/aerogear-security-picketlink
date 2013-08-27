/*
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jboss.aerogear.security.picketlink.auth;

import org.jboss.aerogear.security.auth.AuthenticationManager;
import org.jboss.aerogear.security.exception.AeroGearSecurityException;
import org.jboss.aerogear.security.exception.HttpStatus;
import org.picketlink.Identity;
import org.picketlink.credential.DefaultLoginCredentials;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.basic.Agent;
import org.picketlink.idm.model.basic.User;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * A <i>AuthenticationManager</i> implementation executes the basic authentication operations for User
 */
@ApplicationScoped
public class AuthenticationManagerImpl implements AuthenticationManager<Agent> {

    @Inject
    private Identity identity;

    @Inject
    private DefaultLoginCredentials credentials;

    @Inject
    private IdentityManager identityManager;

    @Inject
    private CredentialMatcher credentialMatcher;

    /**
     * Logs in the specified User.
     *
     * @param user represents a simple implementation that holds user's credentials.
     * @throws org.jboss.aerogear.security.exception.AeroGearSecurityException
     *          on login failure.
     */
    public boolean login(Agent user, String password) {

        credentials.setUserId(user.getLoginName());
        credentials.setCredential(new Password(password));

        credentialMatcher.validate(user, password);

        if (credentialMatcher.hasExpired()) {
            throw new AeroGearSecurityException(HttpStatus.CREDENTIAL_HAS_EXPIRED);
        } else if (identity.login() != Identity.AuthenticationResult.SUCCESS) {
            throw new AeroGearSecurityException(HttpStatus.AUTHENTICATION_FAILED);
        }

        return true;
    }

    /**
     * Logs out the specified User from the system.
     *
     * @throws org.jboss.aerogear.security.exception.AeroGearSecurityException
     *          on logout failure.
     */
    public void logout() {
        onAuthenticationFailure();

        identity.logout();
    }

    //TODO figure out a best place to put this method
    private void onAuthenticationFailure() {
        if (!identity.isLoggedIn())
            throw new AeroGearSecurityException(HttpStatus.AUTHENTICATION_FAILED);
    }
}
