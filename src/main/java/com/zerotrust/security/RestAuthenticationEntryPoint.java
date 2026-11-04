package com.zerotrust.security;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Unauthenticated requests: API calls get 401 JSON, page requests are
 * redirected to the login page.
 */
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        if (JsonResponses.isApiRequest(request)) {
            JsonResponses.write(response, HttpServletResponse.SC_UNAUTHORIZED, "Authentication required.");
        } else {
            response.sendRedirect(request.getContextPath() + "/login.html");
        }
    }
}
