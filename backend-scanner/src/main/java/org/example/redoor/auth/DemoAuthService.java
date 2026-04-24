package org.example.redoor.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.example.redoor.common.ApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class DemoAuthService {

    private static final Map<String, DemoAccount> ACCOUNTS = Map.of(
            "admin", new DemoAccount("admin123", "ADMIN"),
            "user", new DemoAccount("user123", "USER")
    );

    private final Duration tokenValidity;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public DemoAuthService(@Value("${app.demo-auth.token-validity:PT8H}") Duration tokenValidity) {
        this.tokenValidity = tokenValidity;
    }

    public LoginResponse login(LoginRequest request) {
        purgeExpiredSessions();
        DemoAccount account = ACCOUNTS.get(request.username());
        if (account == null || !account.password().equals(request.password())) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Invalid demo credentials.");
        }

        Instant expiresAt = Instant.now().plus(tokenValidity);
        String token = UUID.randomUUID() + "." + UUID.randomUUID();
        AuthPrincipal principal = new AuthPrincipal(request.username(), account.role());
        sessions.put(token, new Session(principal, expiresAt));

        return new LoginResponse(token, principal.username(), principal.role(), expiresAt);
    }

    public AuthPrincipal requirePrincipal(String token) {
        purgeExpiredSessions();
        Session session = sessions.get(token);
        if (session == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Missing, invalid, or expired bearer token.");
        }
        return session.principal();
    }

    private void purgeExpiredSessions() {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
    }

    private record DemoAccount(String password, String role) {
    }

    private record Session(AuthPrincipal principal, Instant expiresAt) {
    }
}
