package org.example.redoor.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.example.redoor.common.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final DemoAuthService demoAuthService;

    public AuthController(DemoAuthService demoAuthService) {
        this.demoAuthService = demoAuthService;
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return demoAuthService.login(request);
    }

    @GetMapping("/me")
    public AuthPrincipal me(HttpServletRequest request) {
        Object principal = request.getAttribute("authPrincipal");
        if (principal instanceof AuthPrincipal authPrincipal) {
            return authPrincipal;
        }
        throw new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required.");
    }
}
