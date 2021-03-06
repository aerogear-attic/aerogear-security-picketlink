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

package org.jboss.aerogear.security.picketlink.authz;

import org.jboss.aerogear.security.auth.LoggedUser;
import org.jboss.aerogear.security.auth.Secret;
import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.exception.AeroGearSecurityException;
import org.jboss.aerogear.security.exception.HttpStatus;
import org.jboss.aerogear.security.otp.api.Base32;
import org.jboss.aerogear.security.picketlink.auth.CredentialMatcher;
import org.picketlink.Identity;
import org.picketlink.credential.DefaultLoginCredentials;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.credential.Password;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.GroupRole;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.query.IdentityQuery;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;
import java.util.List;
import java.util.Set;

/**
 * <i>IdentityManagement</i> allows to assign a set of roles to User on Identity Manager provider
 */
@ApplicationScoped
public class IdentityManagementImpl implements IdentityManagement<User> {

    private static final String IDM_SECRET_ATTRIBUTE = "serial";

    @Inject
    private CredentialMatcher credentialMatcher;

    @Inject
    private GrantConfiguration grantConfiguration;

    @Inject
    private IdentityManager identityManager;

    @Inject
    private DefaultLoginCredentials credentials;

    @Inject
    private Identity identity;

    @Inject
    private PartitionManager partitionManager;

    /**
     * This method allows to specify which <i>roles</i> must be assigned to User
     *
     * @param roles The list of roles.
     * @return {@link GrantMethods} is a builder which a allows to apply a list of roles to the specified User.
     */
    @Override
    public GrantMethods grant(String... roles) {
        return grantConfiguration.roles(roles);
    }

    /**
     * This method allows to revoke which <i>roles</i> must be revoked to User
     *
     * @param roles The list of roles.
     * @return {@link GrantMethods} is a builder which a allows to revoke a list of roles to the specified User.
     */
    @Override
    public GrantMethods revoke(String... roles) {
        return grantConfiguration.revoke(roles);
    }

    /**
     * Find an User by the username specified
     *
     * @param username
     * @return User
     */
    @Override
    public User findByUsername(String username) throws RuntimeException {
        User user = BasicModel.getUser(identityManager, username);
        if (user == null) {
            throw new AeroGearSecurityException(HttpStatus.CREDENTIAL_NOT_FOUND);
        }
        return user;
    }

    /**
     * Remove an User
     *
     * @param username
     */
    @Override
    public void remove(String username) {
        if (isLoggedIn(username)) {
            throw new AeroGearSecurityException(HttpStatus.ALREADY_LOGGED_IN);
        }
        identityManager.remove(BasicModel.getUser(identityManager, username));

    }

    /**
     * Reset user' password
     *
     * @param user            User credential
     * @param currentPassword current password already registered
     * @param newPassword     new password
     * @throws Exception
     */
    @Override
    public void reset(User user, String currentPassword, String newPassword) {

        credentialMatcher.validate(user, currentPassword);

        if (credentialMatcher.hasExpired() || credentialMatcher.isValid()) {
            this.identityManager.updateCredential(user, new Password(newPassword));
        } else {
            throw new AeroGearSecurityException(HttpStatus.PASSWORD_RESET_FAILED);
        }
    }

    /**
     * This method creates a new User
     *
     * @param user
     */
    @Override
    public void create(User user, String password) {
        identityManager.add(user);
        identityManager.updateCredential(user, new Password(password));
    }

    /**
     * Represents the generated TOTP secret for the current User logged in.
     */
    @Produces
    @Secret
    public String getSecret() {

        User user = (User) identity.getAccount();

        Attribute<String> secret = user.getAttribute(IDM_SECRET_ATTRIBUTE);

        if (secret == null) {
            secret = new Attribute<String>(IDM_SECRET_ATTRIBUTE, Base32.random());
            user.setAttribute(secret);
            this.identityManager.update(user);
        }
        return secret.getValue();
    }

    /**
     * Retrieve the logged user name
     *
     * @return user name
     */
    @Produces
    @LoggedUser
    public String getLogin() {
        String id = null;
        if (identity.isLoggedIn()) {
            id = ((User) identity.getAccount()).getLoginName();
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
                Role retrievedRole = BasicModel.getRole(identityManager, role);
                if (retrievedRole != null && BasicModel.hasRole(partitionManager.createRelationshipManager(), identity.getAccount(), retrievedRole)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Find an User by the id specified
     *
     * @param id
     * @return User
     */
    @Override
    public User findById(long id) throws RuntimeException {
        IdentityQuery<User> query = identityManager.createIdentityQuery(User.class);
        query.setParameter(User.ID, id);
        return query.getResultList().get(0);
    }

    /**
     * Get All the users
     *
     * @param name Role name
     * @return Users by roles
     */
    @Override
    public List<User> findAllByRole(String name) {
        Role role = BasicModel.getRole(identityManager, name);
        IdentityQuery<User> query = identityManager.createIdentityQuery(User.class);
        query.setParameter(GroupRole.ROLE, role);
        return query.getResultList();
    }

    private boolean isLoggedIn(String username) {
        return identity.isLoggedIn() && identity.getAccount().getId().equals(username);
    }
}
