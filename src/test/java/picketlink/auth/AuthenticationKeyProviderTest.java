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

import org.jboss.aerogear.security.idm.AuthenticationKeyProvider;
import org.jboss.aerogear.security.picketlink.idm.AuthenticationKeyProviderImpl;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.picketlink.Identity;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.User;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

@Ignore
public class AuthenticationKeyProviderTest {

    @Mock
    private IdentityManager identityManager;

    @Mock
    private Identity identity;

    @Mock
    private User user;

    @InjectMocks
    private AuthenticationKeyProvider keyProvider;

    private static final String IDM_SECRET_ATTRIBUTE = "serial";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        keyProvider = new AuthenticationKeyProviderImpl();
    }

    @Test
    public void testGetAlreadyExistingSecret() throws Exception {
        Attribute secret = new Attribute(IDM_SECRET_ATTRIBUTE, "32626635656566396334");
        when(user.getAttribute("serial")).thenReturn(secret);
        assertEquals(secret, keyProvider.getSecret());
    }

    @Test
    public void testGetNewSecret() throws Exception {
        assertEquals(20, keyProvider.getSecret().length());
    }
}
