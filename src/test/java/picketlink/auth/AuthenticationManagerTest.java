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

package picketlink.auth;

import org.jboss.aerogear.security.auth.AuthenticationManager;
import org.jboss.aerogear.security.exception.AeroGearSecurityException;
import org.jboss.aerogear.security.model.AeroGearUser;
import org.jboss.aerogear.security.picketlink.auth.AuthenticationManagerImpl;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.picketlink.Identity;
import org.picketlink.credential.DefaultLoginCredentials;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.picketlink.Identity.AuthenticationResult;

public class AuthenticationManagerTest {

    @Mock
    private AeroGearUser user;
    @Mock
    private Identity identity;
    @Mock
    private DefaultLoginCredentials credentials;

    @InjectMocks
    private AuthenticationManager authenticationManager;

    @Before
    public void setUp() {
        authenticationManager = new AuthenticationManagerImpl();
        MockitoAnnotations.initMocks(this);
        when(user.getUsername()).thenReturn("john");
        when(user.getPassword()).thenReturn("123");
    }

    @Test
    public void testLogin() throws Exception {
        AuthenticationResult result = AuthenticationResult.SUCCESS;
        when(identity.login()).thenReturn(result);
        authenticationManager.login(user);
    }

    @Test(expected = AeroGearSecurityException.class)
    public void testInvalidLogin() throws Exception {
        when(identity.isLoggedIn()).thenReturn(false);
        authenticationManager.login(user);
    }

    @Test
    public void testLogout() throws Exception {
        when(identity.isLoggedIn()).thenReturn(true);
        authenticationManager.logout();
        verify(identity).logout();
    }
}
