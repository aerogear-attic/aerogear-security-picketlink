/**
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

package org.jboss.aerogear.security.picketlink.idm;

import org.jboss.aerogear.security.auth.Secret;
import org.jboss.aerogear.security.idm.AuthenticationKeyProvider;
import org.jboss.aerogear.security.otp.api.Base32;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.User;

import javax.enterprise.inject.Produces;
import javax.inject.Inject;

/**
 * Authentication key provider
 */
public class AuthenticationKeyProviderImpl implements AuthenticationKeyProvider {

    private static final String IDM_SECRET_ATTRIBUTE = "serial";

    @Inject
    private Identity identity;

    @Inject
    private IdentityManager identityManager;

    /**
     * Represents the generated secret for the current {@link org.jboss.aerogear.security.model.AeroGearUser} logged in.
     */
    @Produces
    @Secret
    public String getSecret() {

        User user = identity.getUser();

        Attribute<String> secret = user.getAttribute(IDM_SECRET_ATTRIBUTE);

        if (secret == null) {
            secret = new Attribute<String>(IDM_SECRET_ATTRIBUTE, Base32.random());
            user.setAttribute(secret);
            this.identityManager.update(user);
        }
        return secret.getValue();
    }
}
