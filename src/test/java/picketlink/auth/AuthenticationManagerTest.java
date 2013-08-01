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

package picketlink.auth;

import org.jboss.aerogear.security.auth.AuthenticationManager;
import org.jboss.aerogear.security.exception.AeroGearSecurityException;
import org.jboss.aerogear.security.picketlink.auth.AuthenticationManagerImpl;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.picketlink.Identity;
import org.picketlink.credential.DefaultLoginCredentials;
import org.picketlink.idm.model.sample.User;
import org.picketlink.idm.credential.Credentials;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.picketlink.Identity.AuthenticationResult;

public class AuthenticationManagerTest {

    @Mock
    private User user;
    @Mock
    private Identity identity;
    @Mock
    private DefaultLoginCredentials credentials;
    @Mock
    private IdentityManager identityManager;

    @InjectMocks
    private AuthenticationManager authenticationManager;

    @Before
    public void setUp() {
        authenticationManager = new AuthenticationManagerImpl();
        MockitoAnnotations.initMocks(this);
        when(user.getLoginName()).thenReturn("john");
    }

    @Test
    public void testLogin() throws Exception {
        AuthenticationResult result = AuthenticationResult.SUCCESS;
        when(identity.login()).thenReturn(result);
        boolean status = authenticationManager.login(user, "123");
        assertTrue("Login result should return true", status);
    }

    @Test(expected = AeroGearSecurityException.class)
    public void testInvalidLogin() throws Exception {
        when(identity.isLoggedIn()).thenReturn(false);
        when(credentials.getStatus()).thenReturn(Credentials.Status.EXPIRED);
        authenticationManager.login(user, "123");
    }

    @Test
    public void testLogout() throws Exception {
        when(identity.isLoggedIn()).thenReturn(true);
        authenticationManager.logout();
        verify(identity).logout();
    }
}
