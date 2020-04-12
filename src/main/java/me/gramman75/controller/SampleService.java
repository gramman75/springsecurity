package me.gramman75.controller;

import me.gramman75.common.SecurityLog;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

    public void dashboard(){
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        boolean authenticated = authentication.isAuthenticated();
    }

    @Async
    public String asyncService() {
        SecurityLog.log("Async service log");
        System.out.println("Async service");

        return "Async Service";

    }

}
