package org.jboss.aerogear.security.picketlink.spi;

import org.picketlink.authentication.BaseAuthenticator;
import org.picketlink.credential.internal.DefaultLoginCredentials;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.credential.Credentials;
import org.picketlink.idm.credential.internal.Password;
import org.picketlink.idm.credential.internal.UsernamePasswordCredentials;
import org.picketlink.idm.model.User;

import javax.inject.Inject;

public class AeroGearAuthenticator extends BaseAuthenticator {
    @Inject
    IdentityManager identityManager;
    
    @Inject DefaultLoginCredentials credentials;
    
    @Override
    public void authenticate() {
        if (credentials.getPassword() == null) {
            setStatus(AuthenticationStatus.FAILURE);
            return;
        }
        
        UsernamePasswordCredentials creds = new UsernamePasswordCredentials(credentials.getUserId(), 
                (Password) credentials.getCredential());
        identityManager.validateCredentials(creds);
        
        
        if (Credentials.Status.VALID.equals(creds.getStatus())) {
            setStatus(AuthenticationStatus.SUCCESS);
            setUser((User) credentials.getValidatedAgent());
        } else {
            setStatus(AuthenticationStatus.FAILURE);
        }
        
        
        
        
    }
}
