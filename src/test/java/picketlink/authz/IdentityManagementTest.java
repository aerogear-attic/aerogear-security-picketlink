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

package picketlink.authz;

import org.jboss.aerogear.security.authz.IdentityManagement;
import org.jboss.aerogear.security.model.AeroGearUser;
import org.jboss.aerogear.security.picketlink.authz.GrantConfiguration;
import org.jboss.aerogear.security.picketlink.authz.IdentityManagementImpl;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.model.SimpleUser;
import org.picketlink.idm.model.User;
import org.picketlink.idm.query.internal.DefaultIdentityQuery;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.when;

public class IdentityManagementTest {

    @Mock
    private IdentityManager identityManager;

    @Mock
    private DefaultIdentityQuery defaultIdentityQuery;

    @Mock
    private GrantConfiguration grantConfiguration;

    @InjectMocks
    private IdentityManagement identityManagement;

    @Before
    public void setUp() throws Exception {
        List<User> list = new ArrayList<User>();
        list.add(new SimpleUser("john"));

        identityManagement = new IdentityManagementImpl();
        MockitoAnnotations.initMocks(this);
        when(identityManager.getUser(("john"))).thenReturn(new SimpleUser("john"));
        when(identityManager.getUser(("mike"))).thenReturn(null);

        when(identityManager.createIdentityQuery(User.class)).thenReturn(defaultIdentityQuery);
        when(defaultIdentityQuery.getResultList()).thenReturn(list);
    }

    private AeroGearUser buildUser(String username) {
        AeroGearUser aeroGearUser = new AeroGearUser();
        aeroGearUser.setUsername(username);
        aeroGearUser.setEmail(username + "@doe.com");
        aeroGearUser.setPassword("123");
        return aeroGearUser;
    }

    @Test
    public void testGrant() throws Exception {
        AeroGearUser user = buildUser("john");
        String role = "ADMIN";
        when(identityManagement.grant(role)).thenReturn(grantConfiguration);
        identityManagement.grant(role).to(user);
    }

    @Test
    public void testCreate() throws Exception {
        AeroGearUser user = buildUser("john");
        identityManagement.create(user);
        User picketLinkUser = identityManager.getUser("john");
        assertNotNull("User should exist", picketLinkUser);
    }

    @Test
    public void testGet() throws Exception {
        AeroGearUser aeroGearUser = identityManagement.get("john");
        assertNotNull("User should exist", aeroGearUser);
    }

    @Test(expected = RuntimeException.class)
    public void testRemove() throws Exception {
        AeroGearUser user = buildUser("mike");
        identityManagement.remove(user);
        AeroGearUser removedUser = identityManagement.get("mike");
        assertNull("User should not exist", removedUser);
    }

    @Test
    public void testFindUserByRole() throws Exception {
        List<AeroGearUser> list = identityManagement.findAllByRole("simple");
        assertNotNull("User should be found by role", list.get(0));
    }

}
