package me.gramman75.account;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Service;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Service
public class LoginSuccessHandler  extends SavedRequestAwareAuthenticationSuccessHandler implements  AuthenticationSuccessHandler  {

    @Autowired
    AccountRepository accountRepository;

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {

//        SavedRequest savedRequest = (SavedRequest) httpServletRequest.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUES");

        SavedRequest request = requestCache.getRequest(httpServletRequest, httpServletResponse);
        DefaultSavedRequest savedRequest = (DefaultSavedRequest) request;
        String redirectUrl = savedRequest == null ? "/signin" : savedRequest.getServletPath();

        String name = authentication.getName();
        Account byUsername = accountRepository.findByUsername(name);
        System.out.println("byUsername = " + byUsername);
        httpServletResponse.sendRedirect(redirectUrl);


    }
}

