package me.gramman75.config;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.WebApplicationInitializer;

public class AppInitalizer implements WebApplicationInitializer {
    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {
        servletContext.addListener(HttpSessionEventPublisher.class);
    }
}