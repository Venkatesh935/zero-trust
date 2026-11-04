package com.zerotrust.dto;

import java.time.Instant;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.Role;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request and response objects for authentication and user management.
 */
public final class AuthDtos {

    private AuthDtos() {
    }

    public static final String USERNAME_PATTERN = "^[A-Za-z0-9._-]{3,50}$";
    public static final String USERNAME_MESSAGE = "Username must be 3-50 characters: letters, digits, dot, underscore or hyphen.";

    public record LoginRequest(
            @NotBlank(message = "Username is required.") @Size(max = 50) String username,
            @NotBlank(message = "Password is required.") @Size(max = 128) String password) {
    }

    public record RegisterRequest(
            @NotBlank @Pattern(regexp = USERNAME_PATTERN, message = USERNAME_MESSAGE) String username,
            @Size(max = 100) String fullName,
            @Email(message = "Email address is not valid.") @Size(max = 120) String email,
            @NotBlank(message = "Password is required.") @Size(max = 128) String password) {
    }

    public record ChangePasswordRequest(
            @NotBlank(message = "Current password is required.") @Size(max = 128) String currentPassword,
            @NotBlank(message = "New password is required.") @Size(max = 128) String newPassword) {
    }

    public record UserCreateRequest(
            @NotBlank @Pattern(regexp = USERNAME_PATTERN, message = USERNAME_MESSAGE) String username,
            @Size(max = 100) String fullName,
            @Email(message = "Email address is not valid.") @Size(max = 120) String email,
            @NotBlank(message = "Password is required.") @Size(max = 128) String password,
            Role role,
            Boolean enabled) {
    }

    public record UserUpdateRequest(
            @Size(max = 100) String fullName,
            @Email(message = "Email address is not valid.") @Size(max = 120) String email,
            Role role,
            Boolean enabled,
            @Size(max = 128) String password,
            Boolean unlock) {
    }

    public record UserDto(Long id, String username, String fullName, String email, Role role,
            boolean enabled, boolean locked, int failedLoginAttempts, Instant lastLoginAt, Instant createdAt) {

        public static UserDto from(AppUser u) {
            return new UserDto(u.getId(), u.getUsername(), u.getFullName(), u.getEmail(), u.getRole(),
                    u.isEnabled(), u.isLocked(), u.getFailedLoginAttempts(), u.getLastLoginAt(), u.getCreatedAt());
        }
    }

    public record UserRef(Long id, String username) {

        public static UserRef from(AppUser u) {
            return u == null ? null : new UserRef(u.getId(), u.getUsername());
        }
    }

    public record CurrentUserDto(Long id, String username, String fullName, Role role, Instant lastLoginAt) {

        public static CurrentUserDto from(AppUser u) {
            return new CurrentUserDto(u.getId(), u.getUsername(), u.getFullName(), u.getRole(), u.getLastLoginAt());
        }
    }
}
