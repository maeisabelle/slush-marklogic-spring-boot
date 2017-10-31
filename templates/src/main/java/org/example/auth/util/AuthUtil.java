package org.example.auth.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

/**
 * Utility class for URI related actions.
 */
@Component
public class AuthUtil {

	public String getUsername(Authentication authentication) {

		if (authentication != null) {
			if(authentication.getPrincipal() instanceof User){
				return ((User) authentication.getPrincipal()).getUsername();
			} else if(authentication.getDetails() instanceof User){
				return ((User) authentication.getDetails()).getUsername();
			} else {
				return authentication.getPrincipal().toString();
			}
		}

		return null;
    }

	public String getPassword(Authentication authentication) {

		if (authentication != null) {
			if(authentication.getPrincipal() instanceof User){
				return ((User) authentication.getPrincipal()).getPassword();
			} else if(authentication.getDetails() instanceof User){
				return ((User) authentication.getDetails()).getPassword();
			} else {
				return authentication.getCredentials().toString();
			}
		}

		return null;
	}
}