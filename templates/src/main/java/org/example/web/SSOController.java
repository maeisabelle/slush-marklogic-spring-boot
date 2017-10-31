package org.example.web;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@ConditionalOnProperty(value="samlSSOEnabled")
@Controller
@RequestMapping("/saml")
public class SSOController {

    // Logger
    private static final Logger LOG = LoggerFactory
            .getLogger(SSOController.class);

    @Autowired
    private MetadataManager metadata;

    @RequestMapping(value = "/idpSelection", method = RequestMethod.GET)
    public String idpSelection(HttpServletRequest request, Model model) {
        if (!(SecurityContextHolder.getContext().getAuthentication() instanceof AnonymousAuthenticationToken)) {
            LOG.warn("The current user is already logged.");
            return "redirect:/search";
        } else {
            if (isForwarded(request)) {
                Set<String> idps = metadata.getIDPEntityNames();
                for (String idp : idps)
                    LOG.info("Configured Identity Provider for SSO: " + idp);
                model.addAttribute("idps", idps);
                return "idpselection";
            } else {
                LOG.warn("Direct accesses to '/idpSelection' route are not allowed");
                return "redirect:/login";
            }
        }
    }

    /*
     * Checks if an HTTP request has been forwarded by a servlet.
     */
    private boolean isForwarded(HttpServletRequest request){
        if (request.getAttribute("javax.servlet.forward.request_uri") == null)
            return false;
        else
            return true;
    }
}
