package org.example;

import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.http.client.CredentialsProvider;
import org.apache.commons.httpclient.HttpClient;
import org.apache.velocity.app.VelocityEngine;
import org.example.client.*;
import org.example.util.URIUtil;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.MethodInvokingFactoryBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import com.marklogic.spring.http.RestConfig;
import com.marklogic.spring.http.SimpleRestConfig;
import com.marklogic.spring.security.context.SpringSecurityCredentialsProvider;
import com.marklogic.spring.security.web.util.matcher.CorsRequestMatcher;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;
import org.springframework.security.saml.trust.httpclient.TLSProtocolSocketFactory;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Extends Spring Boot's default web security configuration class and hooks in MarkLogic-specific classes from
 * marklogic-spring-web. Feel free to customize as needed.
 */
@Configuration
@EnableWebSecurity
public class Config extends WebSecurityConfigurerAdapter{

    /**
     * Be sure to set this in application.properties
     * To change the authentication process and configure SAML
     */
    @Value("${samlSSOEnabled}")
    protected boolean samlSSOEnabled;
    @Value("${samlEntityId}")
    protected String samlEntityId;
    @Value("${samlKeyStorePath}")
    protected String samlKeyStorePath;
    @Value("${samlKeyStorePassword}")
    protected String samlKeyStorePassword;
    @Value("${samlPrivateKeyAlias}")
    protected String samlPrivateKeyAlias;
    @Value("${samlKeystoreAlias}")
    protected String samlKeystoreAlias;
    @Value("${samlIdpDiscoveryEnabled}")
    protected boolean samlIdpDiscoveryEnabled;
    @Value("${samlIdpMetadataPath}")
    protected String samlIdpMetadataPath;

    @Value("${samlIdpMetadataUrl}")
    private String samlIdpMetadataUrl;

    private Timer backgroundTaskTimer;
    private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager;

    @ConditionalOnProperty(value="samlSSOEnabled")
    @PostConstruct
    public void init() {
        this.backgroundTaskTimer = new Timer(true);
        this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager();
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @PreDestroy
    public void destroy() {
        this.backgroundTaskTimer.purge();
        this.backgroundTaskTimer.cancel();
        this.multiThreadedHttpConnectionManager.shutdown();
    }

    // Initialization of the velocity engine
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }

    // XML parser pool needed for OpenSAML parsing
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }


    // Bindings, encoders and decoders used for creating and parsing messages
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public HttpClient httpClient() {
        return new HttpClient(this.multiThreadedHttpConnectionManager);
    }

    // Provider of default SAML Context
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }

    // Initialization of OpenSAML library
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public static SAMLBootstrap sAMLBootstrap() {
        return new SAMLBootstrap();
    }

    // Logger for SAML messages and events
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }

    // SAML 2.0 WebSSO Assertion Consumer
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }

    // SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // SAML 2.0 Web SSO profile
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }

    // SAML 2.0 Holder-of-Key Web SSO profile
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
        return new WebSSOProfileConsumerHoKImpl();
    }

    // SAML 2.0 ECP profile
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public WebSSOProfileECPImpl ecpprofile() {
        return new WebSSOProfileECPImpl();
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }

    // Setup TLS Socket Factory
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public TLSProtocolConfigurer tlsProtocolConfigurer() {
        return new TLSProtocolConfigurer();
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public ProtocolSocketFactory socketFactory() {
        return new TLSProtocolSocketFactory(keyManager(), null, "default");
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public Protocol socketFactoryProtocol() {
        return new Protocol("https", socketFactory(), 443);
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public MethodInvokingFactoryBean socketFactoryInitialization() {
        MethodInvokingFactoryBean methodInvokingFactoryBean = new MethodInvokingFactoryBean();
        methodInvokingFactoryBean.setTargetClass(Protocol.class);
        methodInvokingFactoryBean.setTargetMethod("registerProtocol");
        Object[] args = {"https", socketFactoryProtocol()};
        methodInvokingFactoryBean.setArguments(args);
        return methodInvokingFactoryBean;
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    // Processor
    @Bean
    public SAMLProcessorImpl processor() {
        Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
        bindings.add(httpRedirectDeflateBinding());
        bindings.add(httpPostBinding());
        bindings.add(artifactBinding(parserPool(), velocityEngine()));
        bindings.add(httpSOAP11Binding());
        bindings.add(httpPAOS11Binding());
        return new SAMLProcessorImpl(bindings);
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
        return new HTTPRedirectDeflateBinding(parserPool());
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public HTTPPostBinding httpPostBinding() {
        return new HTTPPostBinding(parserPool(), velocityEngine());
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        final ArtifactResolutionProfileImpl artifactResolutionProfile =
                new ArtifactResolutionProfileImpl(httpClient());
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile);
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public HTTPSOAP11Binding httpSOAP11Binding() {
        return new HTTPSOAP11Binding(parserPool());
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public HTTPPAOS11Binding httpPAOS11Binding() {
        return new HTTPPAOS11Binding(parserPool());
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding(parserPool());
    }

    /**
     * @return a config class with ML connection properties
     */
    @Bean
    public RestConfig restConfig() {
        return new SimpleRestConfig();
    }

    @Bean
    public CredentialsProvider credentialsProvider() {
        return new SpringSecurityCredentialsProvider();
    }

    /**
     * A REST client that a Spring MVC controller can use for proxying requests to MarkLogic. By default, uses
     *         Spring Security for credentials - this relies on Spring Security not erasing the user's credentials so
     *         that the username/password can be passed to MarkLogic on every request for authentication.
     * @return
     */
    @Bean
    public DigestRestClient digestRestClient() {
        return new DigestRestClient();
    }

    /**
     * We seem to need this defined as a bean; otherwise, aspects of the default Spring Boot security will still remain.
     *
     * @return
     */
    @Bean
    public DigestAuthenticationManager digestAuthenticationManager() {
        return new DigestAuthenticationManager();
    }

    /**
     * Loads RestTemplate {@link org.springframework.web.client.RestTemplate} objects wired for Digest authentication.
     *
     * @return
     */
    @Bean
    public DigestRestTemplateLoader digestRestTemplateLoader() {
        return new DigestRestTemplateLoader();
    }

    /**
     * Utility class for URI actions (decoding, etc.).
     * @return
     */
    @Bean
    public URIUtil uriUtil() {
        return new URIUtil();
    }

    /*
      Servlet Filter to compress large http responses.

      Superseeded by the configuration in application.properties for Spring Boot which ONLY takes effect on embedded Tomcat.
          server.compression.enabled=true
          server.compression.min-response-size=128

      UNCOMMENT the following bean to enable compression on standalone application server deployment as an alternative to
           container-based configuration.
      Requires the following in build.gradle:
         compile ("com.github.ziplet:ziplet:2.2.0"){
             exclude group: 'javax.servlet', module: 'servlet-api'
             exclude group: 'org.slf4j', module: 'slf4j-api'
         }

       @ Bean
        public Filter compressingFilter() {
            return new CompressingFilter();
        }
     */

    /**
     * Sets MarkLogicAuthenticationProvider as the authentication manager, which overrides the in-memory authentication
     * manager that Spring Boot uses by default.  Configured to clear the credentials from the {@link Authentication}
     * object after authenticating.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        if(samlSSOEnabled) {
            auth.authenticationProvider(samlAuthenticationProvider());
        } else {
            super.configure(auth);
            auth.parentAuthenticationManager(digestAuthenticationManager());
            auth.eraseCredentials(true);
        }
    }

    // SAML Authentication Provider responsible for validating of received SAML messages
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLAuthenticationProvider samlAuthenticationProvider() {
        return new SAMLAuthenticationManager();
    }

    /**
     * Returns the authentication manager currently used by Spring.
     * It represents a bean definition with the aim allow wiring from
     * other classes performing the Inversion of Control (IoC).
     *
     * @throws  Exception
     */
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * Configures what requests require authentication and which ones are always permitted. Uses CorsRequestMatcher to
     * allow for certain requests - e.g. put/post/delete requests - to be proxied successfully back to MarkLogic.
     *
     * This uses a form login by default, as for many MarkLogic apps (particularly demos), it's convenient to be able to
     * easily logout and login as a different user to show off security features. Spring Security has a very plain form
     * login page - you can customize this, just google for examples.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if(samlSSOEnabled) {

            http.httpBasic().authenticationEntryPoint(samlEntryPoint());

            http.csrf().disable();

            http.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
                .addFilterAfter(samlFilter(), BasicAuthenticationFilter.class);

            http.authorizeRequests()
                .antMatchers(getAlwaysPermittedPatterns()).permitAll()
                .antMatchers("/error").permitAll()
                .antMatchers("/saml/**").permitAll()
                .anyRequest().authenticated();

            http.formLogin()
                .loginPage("/samllogin").permitAll();

            http.logout()
                .logoutSuccessUrl("/samllogin");

        } else {
            http.csrf().requireCsrfProtectionMatcher(new CorsRequestMatcher()).and().authorizeRequests()
                .antMatchers(getAlwaysPermittedPatterns()).permitAll().anyRequest().authenticated().and().formLogin()
                .loginPage("/login").permitAll();
        }
    }

    // Entry point to initialize authentication, default values taken from properties file
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(metadataGenerator());
    }

    // Filter automatically generates default SP metadata
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setEntityId(samlEntityId);
        metadataGenerator.setExtendedMetadata(extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(samlIdpDiscoveryEnabled);
        metadataGenerator.setKeyManager(keyManager());
        return metadataGenerator;
    }

    // Setup advanced info about metadata
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public ExtendedMetadata extendedMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();
        extendedMetadata.setIdpDiscoveryEnabled(samlIdpDiscoveryEnabled);
        extendedMetadata.setSignMetadata(false);
        extendedMetadata.setEcpEnabled(true);
        return extendedMetadata;
    }

    //
	/*
		This is the central storage of cryptographic keys
		If you need to change the IDP and keystore password,
		update and run src/main/resources/saml/update-certificate.sh,
		and make sure the samlKeyStorePassword here is the same as KEYSTORE_PASSWORD
	*/
    @ConditionalOnProperty(value="samlSSOEnabled")
	@Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        Resource storeFile = loader
                .getResource("classpath:" + samlKeyStorePath);
        Map<String, String> passwords = new HashMap<>();
        passwords.put(samlPrivateKeyAlias, samlKeyStorePassword);
        return new JKSKeyManager(storeFile, samlKeyStorePassword, passwords, samlPrivateKeyAlias);
    }

    /**
     * Define the security filter chain in order to support SSO Auth by using SAML 2.0
     *
     * @return Filter chain proxy
     * @throws Exception
     */
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"),
                samlEntryPoint()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"),
                samlLogoutFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
                metadataDisplayFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"),
                samlWebSSOProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
                samlWebSSOHoKProcessingFilter()));
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"),
                samlLogoutProcessingFilter()));
        if(samlIdpDiscoveryEnabled) {
            chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
                    samlIDPDiscovery()));
        }
        return new FilterChainProxy(chains);
    }

    // Overrides default logout processing filter with the one processing SAML
    // messages
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(successLogoutHandler(),
                new LogoutHandler[] { logoutHandler() },
                new LogoutHandler[] { logoutHandler() });
    }

    // Handler for successful logout
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/");
        return successLogoutHandler;
    }

    // Logout handler terminating local session
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler =
                new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }

    // The filter is waiting for connections on URL suffixed with filterSuffix
    // and presents SP metadata there
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }

    // Processing filter for WebSSO profile messages
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }

    // Handler deciding where to redirect user after successful login
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/");
        return successRedirectHandler;
    }

    // Handler deciding where to redirect user after failed login
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler failureHandler =
                new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/error");
        return failureHandler;
    }

    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
        SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
        samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
        samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
        return samlWebSSOHoKProcessingFilter;
    }

    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful
    // global logout
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(successLogoutHandler(),
                logoutHandler());
    }

    // IDP Discovery Service
    @ConditionalOnProperty(value="samlSSOEnabled")
    @Bean
    public SAMLDiscovery samlIDPDiscovery() {
        SAMLDiscovery idpDiscovery = new SAMLDiscovery();
        idpDiscovery.setIdpSelectionPath("/saml/idpSelection");
        return idpDiscovery;
    }

    @ConditionalOnExpression("${samlSSOEnabled:true} && ${samlIdpDiscoveryEnabled:true}")
    @Bean
    @Qualifier("idp-ssocircle")
    public ExtendedMetadataDelegate idpExtendedMetadataProvider()
            throws MetadataProviderException {
        HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(
                this.backgroundTaskTimer, httpClient(), samlIdpMetadataUrl);
        httpMetadataProvider.setParserPool(parserPool());
        ExtendedMetadataDelegate extendedMetadataDelegate =
                new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(true);
        extendedMetadataDelegate.setMetadataRequireSignature(false);
        backgroundTaskTimer.purge();
        return extendedMetadataDelegate;
    }

    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @ConditionalOnExpression("${samlSSOEnabled:true} && ${samlIdpDiscoveryEnabled:true}")
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(idpExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }

    //Be sure to set the idp metadata path if idpDiscovery is disabled
    @ConditionalOnExpression("${samlSSOEnabled:true} && ${samlIdpDiscoveryEnabled:false}")
    @Bean
    public ExtendedMetadataDelegate idpFilesytemMetadataProvider()
            throws MetadataProviderException, IOException {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        File idpMetadataPath = loader
                .getResource("classpath:" + samlIdpMetadataPath).getFile();
        FilesystemMetadataProvider filesystemMetadataProvider = new FilesystemMetadataProvider(idpMetadataPath);
        filesystemMetadataProvider.setParserPool(parserPool());
        ExtendedMetadataDelegate extendedMetadataDelegate =
                new ExtendedMetadataDelegate(filesystemMetadataProvider, extendedMetadata());
        extendedMetadataDelegate.setMetadataTrustCheck(true);
        extendedMetadataDelegate.setMetadataRequireSignature(true);
        return extendedMetadataDelegate;
    }

    /**
     * Defines a set of URLs that are always permitted - these are based on the presumed contents of the
     * src/main/resources/static directory.
     *
     * @return
     */
    protected String[] getAlwaysPermittedPatterns() {
        return new String[] { "/bower_components/**", "/fonts/**", "/images/**", "/styles/**" };
    }

}
