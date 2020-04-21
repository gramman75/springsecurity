package me.gramman75.config;

import me.gramman75.account.Account;
import me.gramman75.account.AccountRepository;
import me.gramman75.account.AccountService;
import me.gramman75.account.LoginSuccessHandler;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.util.PathMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@EnableWebSecurity
// @Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    LoginSuccessHandler loginSuccessHandler;

    @Autowired
    AccountService accountService;

    public SecurityExpressionHandler expressionHandler() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    //
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .addFilter(digestAuthenticationFilter())
            .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint())
            .and()
            .csrf().disable()
            .authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                .mvcMatchers("/security").fullyAuthenticated()
                .anyRequest().authenticated()
                .expressionHandler(expressionHandler());

        http.formLogin(form -> form.loginPage("/signin").permitAll());

        // http.formLogin().loginPage("/signin").loginProcessingUrl("/login").usernameParameter("name")
        //         .passwordParameter("pw").successHandler(loginSuccessHandler).permitAll();

        // .successHandler(new AuthenticationSuccessHandler() {
        // @Autowired
        // AccountRepository accountRepository;
        //
        // @Override
        // public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
        // HttpServletResponse httpServletResponse, Authentication authentication)
        // throws IOException, ServletException {
        // String name = authentication.getName();
        // Account byUsername = accountRepository.findByUsername(name);
        // System.out.println("account = " + byUsername);
        // }
        // });
        // .defaultSuccessUrl("/");
        // http.httpBasic();
        http.logout().logoutUrl("/logout").logoutSuccessUrl("/");

        http.rememberMe().userDetailsService(accountService);

        http.exceptionHandling()
                // .accessDeniedPage("/access-denied")
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response,
                            AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        Object principal1 = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                        UserDetails principal = (UserDetails) principal1;
                        System.out.println("principal = " + principal);
                        response.sendRedirect("/access-denied");
                    }
                });

        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
    }

    DigestAuthenticationFilter digestAuthenticationFilter() {
        DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
        filter.setUserDetailsService(accountService);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint());

        return filter;
    }

    private DigestAuthenticationEntryPoint authenticationEntryPoint() {
        DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
        entryPoint.setRealmName("realmName");
        entryPoint.setKey("3028472b-da34-4501-bfd8-a355c42bdf92");

        return entryPoint;
    }

    //
    // @Override
    // protected void configure(AuthenticationManagerBuilder auth) throws Exception
    // {
    // auth.inMemoryAuthentication()
    // .withUser("gramman75").password("{noop}123").roles("USER").and()
    // .withUser("admin").password("{noop}!@#").roles("ADMIN");
    // }
  
}
