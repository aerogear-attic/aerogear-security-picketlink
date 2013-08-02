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

import org.jboss.aerogear.security.authz.IdentityManagement;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.model.sample.Role;
import org.picketlink.idm.model.sample.SampleModel;
import org.picketlink.idm.model.sample.User;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 * <i>GrantMethods</i> implementation is a builder to apply roles to User
 */
@ApplicationScoped
public class GrantConfiguration implements IdentityManagement.GrantMethods<User> {

    @Inject
    private IdentityManager identityManager;
    @Inject
    private Identity identity;

    @Inject
    private PartitionManager partitionManager;

    private List<Role> list;

    /**
     * This method specifies which roles will be applied to User
     *
     * @param roles Array of roles
     * @return builder implementation
     */
    @Override
    public GrantConfiguration roles(String[] roles) {
        list = new ArrayList<Role>();
        for (String role : roles) {
            Role newRole = SampleModel.getRole(identityManager, role);
            if (newRole == null) {
                newRole = new Role(role);
                identityManager.add(newRole);
            }
            list.add(newRole);
        }
        return this;
    }

    /**
     * This method allows to revoke which <i>roles</i> must be revoked to User
     * @param roles List of roles to be revoked
     */
    @Override
    public GrantConfiguration revoke(String... roles) {
        list = new ArrayList<Role>();
        if (identity.isLoggedIn()) {
            for (String role : roles) {
                Role retrievedRole = identityManager.getRole(role);
                if (retrievedRole != null && identityManager.hasRole(identity.getAgent(), retrievedRole)) {
                    list.add(retrievedRole);
                }
            }
        }
        return this;
    }

    /**
     * This method revokes roles specified on {@link IdentityManagement#revoke(String...)}
     *
     * @param user represents a simple user's implementation to hold credentials.
     */
    @Override
    public void to(User user) {
        for (Role role : list) {
            this.identityManager.revokeRole(user, role);
        }
    }

    /**
     * This method applies roles specified on {@link IdentityManagement#grant(String...)}
     *
     * @param username represents a simple user's implementation to hold credentials.
     */
    @Override
    public void to(String username) {

        User picketLinkUser = SampleModel.getUser(identityManager, username);

        for (Role role : list) {
            SampleModel.grantRole(partitionManager.createRelationshipManager(), picketLinkUser, role);
        }

    }
}
