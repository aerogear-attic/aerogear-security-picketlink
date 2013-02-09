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

package picketlink.idm;

import org.jboss.aerogear.security.picketlink.idm.AeroGearCredentialImpl;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.model.SimpleUser;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

public class AeroGearCredentialTest {

    @Mock
    private Identity identity;

    @Mock
    private IdentityManager identityManager;

    @InjectMocks
    private AeroGearCredentialImpl aeroGearCredential;

    @Before
    public void setUp() {
        aeroGearCredential = new AeroGearCredentialImpl();
        MockitoAnnotations.initMocks(this);
        when(identity.getUser()).thenReturn(new SimpleUser("john"));
        when(identity.isLoggedIn()).thenReturn(true);
    }


    @Test
    @Ignore
    public void testHasRoles() throws Exception {
        Set<String> roles = new HashSet<String>(Arrays.asList("manager", "developer"));
        assertTrue(aeroGearCredential.hasRoles(roles));
    }

    @Test
    public void testRoleNotFound() throws Exception {
        Set<String> roles = new HashSet<String>(Arrays.asList("guest"));
        assertFalse(aeroGearCredential.hasRoles(roles));
    }
}
