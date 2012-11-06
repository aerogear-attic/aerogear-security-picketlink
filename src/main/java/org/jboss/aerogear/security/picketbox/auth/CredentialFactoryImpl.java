/*
 * JBoss, Home of Professional Open Source
 * Copyright 2012, Red Hat, Inc., and individual contributors
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

package org.jboss.aerogear.security.picketbox.auth;

import org.jboss.aerogear.security.auth.CredentialFactory;
import org.jboss.aerogear.security.model.AeroGearUser;
import org.picketbox.core.authentication.credential.OTPCredential;
import org.picketlink.credential.Credential;
import org.picketlink.credential.LoginCredentials;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;

@ApplicationScoped
public class CredentialFactoryImpl implements CredentialFactory, Credential {

    private Object credential;

    @Inject
    private LoginCredentials loginCredentials;

    public void setCredential(AeroGearUser user) {
        this.credential = new OTPCredential(user.getId(), user.getPassword(), user.getOtp());
        loginCredentials.setCredential(this);
    }

    @Override
    public Object getValue() {
        return credential;
    }
}
