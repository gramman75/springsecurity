package me.gramman75.account;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.session.InvalidSessionStrategy;

public class InvalidSessionHandler implements InvalidSessionStrategy {


    @Override
    public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        
        System.out.println("Invalid Session url :" + request.getRequestURI());

        response.sendRedirect(request.getRequestURI());

    }


}