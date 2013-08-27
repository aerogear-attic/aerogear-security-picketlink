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

package picketlink.authz;

import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.picketlink.authz.GrantConfiguration;
import org.jboss.aerogear.security.picketlink.authz.IdentityManagementImpl;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.PartitionManager;
import org.picketlink.idm.model.basic.Role;
import org.picketlink.idm.model.basic.BasicModel;
import org.picketlink.idm.model.basic.User;
import org.picketlink.idm.query.internal.DefaultIdentityQuery;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityManagementTest {

    @Mock
    private Identity identity;

    @Mock
    private IdentityManager identityManager;

    @Mock
    private DefaultIdentityQuery defaultIdentityQuery;

    @Mock
    private GrantConfiguration grantConfiguration;

    @Mock
    private PartitionManager partitionManager;

    @InjectMocks
    private IdentityManagement identityManagement = new IdentityManagementImpl();

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        List<User> list = new ArrayList<User>();
        list.add(new User("john"));

        when(identity.getAccount()).thenReturn(new User("john"));
        when(identity.isLoggedIn()).thenReturn(true);

        when(identityManager.createIdentityQuery(User.class)).thenReturn(defaultIdentityQuery);
        when(defaultIdentityQuery.getResultList()).thenReturn(list);

    }

    private User buildUser(String username) {
        User user = mock(User.class);
        when(user.getLoginName()).thenReturn(username);
        when(user.getEmail()).thenReturn(username + "@doe.com");
        return user;
    }

    @Test
    public void testGrant() throws Exception {
        String role = "ADMIN";
        when(identityManagement.grant(role)).thenReturn(grantConfiguration);
        identityManagement.grant(role).to("john");
    }

    @Test
    @Ignore
    public void testCreate() throws Exception {
        User user = buildUser("john");
        identityManagement.create(user, "123");
        User picketLinkUser = BasicModel.getUser(identityManager, "john");
        assertEquals("User should exist", picketLinkUser.getLoginName(), user.getLoginName());
    }

    @Test(expected = RuntimeException.class)
    public void testRemove() throws Exception {
        identityManagement.remove("mike");
        User removedUser = (User) identityManagement.findByUsername("mike");
        assertNull("User should not exist", removedUser);
    }

    @Test
    @Ignore
    public void testHasRoles() throws Exception {
        Role role = mock(Role.class);
        when(BasicModel.getRole(identityManager, eq("manager"))).thenReturn(role);
//        when(BasicModel.hasRole(any(User.class), eq(role))).thenReturn(true);
        Set<String> roles = new HashSet<String>(Arrays.asList("manager", "developer"));
        assertTrue(identityManagement.hasRoles(roles));
    }

    @Test
    @Ignore
    public void testRoleNotFound() throws Exception {
        Set<String> roles = new HashSet<String>(Arrays.asList("guest"));
        assertFalse(identityManagement.hasRoles(roles));
    }

}
