package me.gramman75.common;

import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityLog {
    public static void log(String message) {
         System.out.println(message);
        Thread thread = Thread.currentThread();
        System.out.println("Thread name : " + thread.getName());
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        System.out.println("principal = " + principal);
    }
}
