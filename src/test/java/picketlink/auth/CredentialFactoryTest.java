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

import org.jboss.aerogear.security.model.AeroGearUser;
import org.jboss.aerogear.security.picketlink.auth.CredentialFactoryImpl;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.picketlink.credential.internal.DefaultLoginCredentials;

public class CredentialFactoryTest {

    @Mock
    private DefaultLoginCredentials loginCredentials;

    @InjectMocks
    private CredentialFactoryImpl credentialFactory;

    @Before
    public void setUp() throws Exception {
        credentialFactory = new CredentialFactoryImpl();
        MockitoAnnotations.initMocks(this);
    }

    private AeroGearUser buildUser(String username, String password) {
        AeroGearUser aeroGearUser = new AeroGearUser();
        aeroGearUser.setUsername(username);
        aeroGearUser.setPassword(password);
        aeroGearUser.setEmail(username + "@doe.com");
        return aeroGearUser;
    }

    @Test
    @Ignore
    public void testGetSimpleCredential() throws Exception {
        credentialFactory.setCredential(buildUser("john", "123"));
    }

    @Test
    @Ignore
    public void testGetOtpCredential() throws Exception {
        credentialFactory.setCredential(buildUser("john", null));
    }
}
