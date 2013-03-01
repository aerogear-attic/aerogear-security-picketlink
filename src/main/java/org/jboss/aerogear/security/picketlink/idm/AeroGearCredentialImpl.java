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

import org.jboss.aerogear.security.auth.LoggedUser;
import org.jboss.aerogear.security.auth.Roles;
import org.jboss.aerogear.security.idm.AeroGearCredential;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.model.Role;
import org.picketlink.idm.model.SimpleRole;
import org.picketlink.idm.query.IdentityQuery;

import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Represents the current logged in Credential
 */
public class AeroGearCredentialImpl implements AeroGearCredential {

    @Inject
    private Identity identity;

    @Inject
    private IdentityManager identityManager;

    /**
     * Represents the current {@link org.jboss.aerogear.security.model.AeroGearUser} logged in.
     */
    @Produces
    @LoggedUser
    public String getLogin() {
        String id = null;
        if (identity.isLoggedIn()) {
            id = identity.getUser().getLoginName();
        }
        return id;
    }

    /**
     * Role validation against the IDM
     *
     * @param roles roles to be checked
     * @return returns true if the current logged in has roles at the IDM, false otherwise
     */
    @Override
    public boolean hasRoles(Set<String> roles) {
        if (identity.isLoggedIn()) {
            for (String role : roles) {
                if (identityManager.hasRole(identity.getUser(), identityManager.getRole(role))) {
                    return true;
                }
            }
        }
        return false;
    }

    @Produces
    @Roles
    public List<String> getRoles() {

        List<String> roles = new ArrayList();

        if (identity.isLoggedIn()) {
            IdentityQuery<Role> query = identityManager.createIdentityQuery(Role.class);
            query.setParameter(Role.ROLE_OF, new Object[]{identity.getUser()});
            for (Role role : query.getResultList()) {
                roles.add(role.getName());
            }
        }
        return roles;
    }
}