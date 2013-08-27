/*
 * JBoss, Home of Professional Open Source
 *  Copyright Red Hat, Inc., and individual contributors.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.jboss.aerogear.security.picketlink.auth;

import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.credential.UsernamePasswordCredentials;
import org.picketlink.idm.model.basic.Agent;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * Responsible for matching credentials against the IDM
 */

@ApplicationScoped
public class CredentialMatcher {

    @Inject
    private IdentityManager identityManager;

    private Credentials credential;

    /**
     * Check if the credential is valid
     *
     * @return boolean
     */
    public boolean isValid() {
        return credential.getStatus().equals(Credentials.Status.VALID);
    }

    /**
     * Check if the credential has already expired
     *
     * @return boolean
     */
    public boolean hasExpired() {
        return credential.getStatus().equals(Credentials.Status.EXPIRED);
    }

    /**
     * Validate if the credential provided matches
     *
     * @param user
     * @param password
     * @return builder implementation
     */
    public void validate(Agent user, String password) {
        Credentials credential = new UsernamePasswordCredentials(user.getLoginName(), new Password(password));
        identityManager.validateCredentials(credential);
        this.credential = credential;
    }
}
