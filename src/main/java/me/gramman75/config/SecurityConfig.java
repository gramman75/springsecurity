package me.gramman75.config;

import me.gramman75.account.Account;
import me.gramman75.account.AccountRepository;
import me.gramman75.account.AccountService;
import me.gramman75.account.InvalidSessionHandler;
import me.gramman75.account.LoginFailureHandler;
import me.gramman75.account.LoginSuccessHandler;
import me.gramman75.common.CustomOAuth2UserService;
import me.gramman75.common.CustomOidcUserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer.ConcurrencyControlConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.util.PathMatcher;
import org.springframework.security.core.GrantedAuthority;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

@EnableWebSecurity
// @Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    LoginSuccessHandler loginSuccessHandler;

    @Autowired
    AccountService accountService;

    // @Autowired
    // UserDetailsService users;

    public SecurityExpressionHandler expressionHandler() {
        final RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        final DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    //
    @Override
    public void configure(final WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
            // .addFilter(digestAuthenticationFilter())
            // .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
            // .and()
            .csrf().disable()
            .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup", "/invalidSession","/oauth","/redirect").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                .mvcMatchers("/security").fullyAuthenticated()
                .anyRequest().authenticated()
                .expressionHandler(expressionHandler());


        http.formLogin()
            .loginPage("/signin").permitAll()
            .loginProcessingUrl("/login")
                .usernameParameter("name")
                .passwordParameter("pw")
            .successHandler(loginSuccessHandler)
            .failureHandler(new LoginFailureHandler())
            .and()
            .oauth2Login(oauth-> 
                oauth.userInfoEndpoint(userInfo -> 
                    userInfo.userAuthoritiesMapper(this.userAuthoritiesMapper())
                            .userService(new CustomOAuth2UserService())
                            .oidcUserService(new CustomOidcUserService())
                )
            );

        // http.httpBasic();

        // http.oauth2Login();
        // .loginPage(loginPage);

        http.logout()
            .logoutUrl("/logout")
            .logoutSuccessUrl("/")
            .deleteCookies("JSESSIONID");

        http.rememberMe()
            .key("myKey")
            .rememberMeCookieName("myCookieName")
            .useSecureCookie(true)
            .tokenValiditySeconds(1000)
            .userDetailsService(accountService);

        http.exceptionHandling()
                // .accessDeniedPage("/access-denied")
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(final HttpServletRequest request, final HttpServletResponse response,
                            final AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        final Object principal1 = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                        final UserDetails principal = (UserDetails) principal1;
                        System.out.println("principal = " + principal);
                        response.sendRedirect("/access-denied");
                    }
                });

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);

        http.sessionManagement()
            // .invalidSessionUrl("/invalidSession")
            .maximumSessions(1);

    }

    DigestAuthenticationFilter digestAuthenticationFilter() {
        final DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
        filter.setUserDetailsService(accountService);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint());

        return filter;
    }

    private DigestAuthenticationEntryPoint authenticationEntryPoint() {
        final DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
        entryPoint.setRealmName("realmName");
        entryPoint.setKey("3028472b-da34-4501-bfd8-a355c42bdf92");

        return entryPoint;
    }

    //
    // @Override
    // protected void configure(final AuthenticationManagerBuilder auth) throws Exception
    // {
    //     auth.userDetailsService(users);
    // }


    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            
            authorities.stream().forEach(authority ->{
                if (OidcUserAuthority.class.isInstance(authority)) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;
                    
                    mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                    OAuth2UserAuthority auth2UserAuthority = (OAuth2UserAuthority)authority;
                    mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                    // mappedAuthorities.add(auth2UserAuthority);
                }

            });

            return mappedAuthorities;
        };

        
    }
  
}
