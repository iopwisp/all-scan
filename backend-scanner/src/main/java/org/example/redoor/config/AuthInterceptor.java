package org.example.redoor.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.redoor.auth.DemoAuthService;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AuthInterceptor implements HandlerInterceptor {

    private final DemoAuthService demoAuthService;

    public AuthInterceptor(DemoAuthService demoAuthService) {
        this.demoAuthService = demoAuthService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // Skip auth for OPTIONS (CORS preflight), login endpoint, and H2 console
        if (HttpMethod.OPTIONS.matches(request.getMethod())
                || "/api/auth/login".equals(request.getRequestURI())
                || request.getRequestURI().startsWith("/h2-console")) {
            return true;
        }

        // If a Bearer token is provided, validate it; otherwise allow the request through
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring("Bearer ".length()).trim();
            request.setAttribute("authPrincipal", demoAuthService.requirePrincipal(token));
        }

        return true;
    }
}
