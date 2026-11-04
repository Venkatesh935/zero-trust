package com.zerotrust.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.zerotrust.dto.ApiResponse;
import com.zerotrust.dto.AuthDtos.ChangePasswordRequest;
import com.zerotrust.dto.AuthDtos.CurrentUserDto;
import com.zerotrust.dto.AuthDtos.LoginRequest;
import com.zerotrust.dto.AuthDtos.RegisterRequest;
import com.zerotrust.security.CurrentUserService;
import com.zerotrust.service.AuthService;
import com.zerotrust.service.SettingsService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final CurrentUserService currentUserService;
    private final SettingsService settingsService;

    public AuthController(AuthService authService, CurrentUserService currentUserService,
            SettingsService settingsService) {
        this.authService = authService;
        this.currentUserService = currentUserService;
        this.settingsService = settingsService;
    }

    /** Issues the CSRF token cookie (XSRF-TOKEN) used by the JavaScript client. */
    @GetMapping("/csrf")
    public ApiResponse<Map<String, String>> csrf(CsrfToken token) {
        return ApiResponse.ok(Map.of("headerName", token.getHeaderName(), "token", token.getToken()));
    }

    @PostMapping("/login")
    public ApiResponse<CurrentUserDto> login(@Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        return ApiResponse.ok("Signed in successfully.",
                CurrentUserDto.from(authService.login(request, httpRequest, httpResponse)));
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        return ApiResponse.ok("Signed out.", null);
    }

    @GetMapping("/me")
    public ApiResponse<CurrentUserDto> me() {
        return ApiResponse.ok(CurrentUserDto.from(currentUserService.currentUser()));
    }

    @GetMapping("/registration-status")
    public ApiResponse<Map<String, Boolean>> registrationStatus() {
        return ApiResponse.ok(Map.of("enabled", settingsService.isRegistrationEnabled()));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok(
                "Registration submitted. An administrator must approve your account before you can sign in.", null));
    }

    @PutMapping("/password")
    public ApiResponse<Void> changePassword(@Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(request);
        return ApiResponse.ok("Password changed successfully.", null);
    }
}
