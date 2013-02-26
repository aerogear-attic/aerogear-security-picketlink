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
import org.jboss.aerogear.security.picketlink.util.Converter;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.SimpleUser;
import org.picketlink.idm.model.User;
import org.picketlink.idm.query.IdentityQuery;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 * <i>IdentityManagement</i> allows to assign a set of roles to {@link org.jboss.aerogear.security.model.AeroGearUser} on Identity Manager provider
 */
@ApplicationScoped
public class IdentityManagementImpl implements IdentityManagement {

    @Inject
    private IdentityManager identityManager;

    @Inject
    private GrantConfiguration grantConfiguration;

    /**
     * This method allows to specify which <i>roles</i> must be assigned to {@link org.jboss.aerogear.security.model.AeroGearUser}
     *
     * @param roles The list of roles.
     * @return {@link GrantMethods} is a builder which a allows to apply a list of roles to the specified {@link org.jboss.aerogear.security.model.AeroGearUser}.
     */
    @Override
    public GrantMethods grant(String... roles) {
        return grantConfiguration.roles(roles);
    }

    @Override
    public AeroGearUser get(String id) throws RuntimeException {
        User user = identityManager.getUser(id);
        if (user == null) {
            throw new RuntimeException("User do not exist");
        }
        return Converter.convertToAerogearUser(identityManager.getUser(id));
    }

    @Override
    public void remove(AeroGearUser aeroGearUser) {
        identityManager.remove(identityManager.getUser(aeroGearUser.getUsername()));
    }

    @Override
    public List<AeroGearUser> findAllByRole(String role) {
        List aerogearUsers = new ArrayList();
        IdentityQuery<User> query = identityManager.createIdentityQuery(User.class);
        query.setParameter(User.HAS_ROLE, new String[]{role});
        List<User> result = query.getResultList();
        for (User user : result) {
            aerogearUsers.add(Converter.convertToAerogearUser(user));
        }
        return aerogearUsers;
    }

    /**
     * This method creates a new {@link AeroGearUser}
     *
     * @param aeroGearUser
     */
    @Override
    public void create(AeroGearUser aeroGearUser) {
        User picketLinkUser = new SimpleUser(aeroGearUser.getUsername());
        picketLinkUser.setEmail(aeroGearUser.getEmail());
        picketLinkUser.setFirstName(aeroGearUser.getFirstname());
        picketLinkUser.setLastName(aeroGearUser.getLastname());
        identityManager.add(picketLinkUser);
        /*
         * Disclaimer: PlainTextPassword will encode passwords in SHA-512 with SecureRandom-1024 salt
         * See http://lists.jboss.org/pipermail/security-dev/2013-January/000650.html for more information
         */
        identityManager.updateCredential(picketLinkUser, new Password(aeroGearUser.getPassword()));
    }
}
