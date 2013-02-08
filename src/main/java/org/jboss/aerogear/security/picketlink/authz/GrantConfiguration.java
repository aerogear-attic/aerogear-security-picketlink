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

package org.jboss.aerogear.security.picketlink.authz;

import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.model.AeroGearUser;
import org.jboss.aerogear.security.picketlink.spi.AeroGear;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.internal.Password;
import org.picketlink.idm.model.Role;
import org.picketlink.idm.model.SimpleRole;
import org.picketlink.idm.model.User;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 * <i>GrantMethods</i> implementation is a builder to apply roles to {@link AeroGearUser}
 */
@ApplicationScoped
public class GrantConfiguration implements IdentityManagement.GrantMethods {

    @Inject @AeroGear
    private IdentityManager identityManager;

    private List<Role> list;

    /**
     * This method specifies which roles will be applied to {@link AeroGearUser}
     *
     * @param roles Array of roles
     * @return builder implementation
     */
    public GrantConfiguration roles(String[] roles) {
        list = new ArrayList<Role>();
        for (String role : roles) {
            Role newRole = identityManager.getRole(role);
            if (newRole == null) {
                newRole = new SimpleRole(role);
                identityManager.add(newRole);
            }
            list.add(newRole);
        }
        return this;
    }

    /**
     * This method applies roles specified on {@link IdentityManagement#grant(String...)}
     *
     * @param aeroGearUser represents a simple user's implementation to hold credentials.
     */
    @Override
    public void to(AeroGearUser aeroGearUser) {

        User picketLinkUser = identityManager.getUser(aeroGearUser.getUsername());

        /*
         * Disclaimer: PlainTextPassword will encode passwords in SHA-512 with SecureRandom-1024 salt
         * See http://lists.jboss.org/pipermail/security-dev/2013-January/000650.html for more information
         */
        identityManager.updateCredential(picketLinkUser, new Password(aeroGearUser.getPassword()));

        for (Role role : list) {
            identityManager.grantRole(picketLinkUser, role);
        }

    }
}
