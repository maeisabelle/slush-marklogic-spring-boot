package  org.example.auth.saml;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    // Logger
    private static final Logger LOG = LoggerFactory.getLogger(SAMLUserDetailsServiceImpl.class);

    @Value("${samlPasswordSalt}")
    protected String samlPasswordSalt;

    public User loadUserBySAML(SAMLCredential credential)
            throws UsernameNotFoundException {

        /**
         * Customize this one according to your IdP
         * For ssocircle, the username is found under the Attribute UserID
         * This is also where you parse the group where the user belong to
         */

        String userID = credential.getAttributeAsString("UserID");
        LOG.info(userID + " logged in");

        //TODO - generate password based on the userID and a secret
        ShaPasswordEncoder encoder = new ShaPasswordEncoder(256);
        String password = encoder.encodePassword(userID,samlPasswordSalt);

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);

        return new User(userID, password, true, true, true, true, authorities);
    }

}
