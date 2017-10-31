package org.example.client;

import org.example.auth.saml.SAMLUserDetailsServiceImpl;
import org.example.auth.util.AuthUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.SAMLAuthenticationProvider;

public class SAMLAuthenticationManager extends SAMLAuthenticationProvider {

    @Autowired
    private DigestAuthenticationManager digestAuthenticationManager;

    @Autowired
    private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

    @Autowired
    private AuthUtil authUtil;

    public SAMLAuthenticationManager() {
        super();
        super.setUserDetails(samlUserDetailsServiceImpl);
        super.setForcePrincipalAsString(false);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Authentication newAuthentication = super.authenticate(authentication);

        String username = authUtil.getUsername(newAuthentication);
        String password = authUtil.getPassword(newAuthentication);
        //forward to digestAuthenticationManager to get an Authentication object
        return digestAuthenticationManager.createSession(username, password, newAuthentication.getAuthorities());

    }
}
