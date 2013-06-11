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


import org.jboss.aerogear.security.auth.LoggedUser;
import org.jboss.aerogear.security.auth.Secret;
import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.model.AeroGearUser;
import org.jboss.aerogear.security.otp.api.Base32;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.SimpleUser;
import org.picketlink.idm.model.User;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * <i>IdentityManagement</i> allows to assign a set of roles to {@link org.jboss.aerogear.security.model.AeroGearUser} on Identity Manager provider
 */
@ApplicationScoped
public class IdentityManagementImpl implements IdentityManagement {

    private static final String IDM_SECRET_ATTRIBUTE = "serial";

    @Inject
    private IdentityManager identityManager;

    @Inject
    private GrantConfiguration grantConfiguration;

    @Inject
    private Identity identity;


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
    public AeroGearUser findByUsername(String username) throws RuntimeException {
        AeroGearUser user = (AeroGearUser) identityManager.getUser(username);
        if (user == null) {
            throw new RuntimeException("AeroGearUser do not exist");
        }
        return user;
    }

    @Override
    public void remove(String username) {
        if (isLoggedIn(username)) {
            throw new RuntimeException("AeroGearUser is logged in");
        }
        identityManager.remove(identityManager.getUser(username));

    }

    /**
     * This method creates a new {@link org.jboss.aerogear.security.model.AeroGearUser}
     *
     * @param user
     */
    @Override
    public void create(AeroGearUser user) {
        org.picketlink.idm.model.User picketLinkUser = new SimpleUser(user.getUsername());
        picketLinkUser.setEmail(user.getEmail());
        identityManager.add(picketLinkUser);
        /*
         * Disclaimer: PlainTextPassword will encode passwords in SHA-512 with SecureRandom-1024 salt
         * See http://lists.jboss.org/pipermail/security-dev/2013-January/000650.html for more information
         */
        identityManager.updateCredential(picketLinkUser, new Password(user.getPassword()));
    }

    /**
     * Represents the generated secret for the current {@link org.jboss.aerogear.security.model.AeroGearUser} logged in.
     */
    @Produces
    @Secret
    public String getSecret() {

        User user = (User) identity.getAgent();

        Attribute<String> secret = user.getAttribute(IDM_SECRET_ATTRIBUTE);

        if (secret == null) {
            secret = new Attribute<String>(IDM_SECRET_ATTRIBUTE, Base32.random());
            user.setAttribute(secret);
            this.identityManager.update(user);
        }
        return secret.getValue();
    }

    @Produces
    @LoggedUser
    public String getLogin() {
        String id = null;
        if (identity.isLoggedIn()) {
            id = identity.getAgent().getLoginName();
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
                if (identityManager.hasRole(identity.getAgent(), identityManager.getRole(role))) {
                    return true;
                }
            }
        }
        return false;
    }

    //TODO Not sure if it's really necessary
    @Override
    public AeroGearUser findById(long id) throws RuntimeException {
        return null;
    }

    //TODO Not sure if it's really necessary
    @Override
    public List<AeroGearUser> findAllByRole(String roleName) {
/*        Role role = identityManager.getRole(roleName);
        List aerogearUsers = new ArrayList();
        IdentityQuery<org.picketlink.idm.model.User> query = identityManager.createIdentityQuery(org.picketlink.idm.model.User.class);
        query.setParameter(org.picketlink.idm.model.User.HAS_ROLE, role);
        List<org.picketlink.idm.model.User> result = query.getResultList();
        for (org.picketlink.idm.model.User user : result) {
            aerogearUsers.add(Converter.convertToAerogearUser(user));
        }
        return aerogearUsers;*/
        return new ArrayList<AeroGearUser>();

    }

    private boolean isLoggedIn(String username) {
        return identity.isLoggedIn() && identity.getAgent().getLoginName().equals(username);
    }
}
