package com.zerotrust.security;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.Role;

/**
 * Authenticated user stored in the HTTP session. The password hash is erased
 * after authentication so it is never kept in the session.
 */
public class UserPrincipal implements UserDetails, CredentialsContainer {

    private static final long serialVersionUID = 1L;

    private final Long id;
    private final String username;
    private final Role role;
    private final boolean enabled;
    private final boolean locked;
    private String passwordHash;

    public UserPrincipal(AppUser user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.role = user.getRole();
        this.enabled = user.isEnabled();
        this.locked = user.isLocked();
        this.passwordHash = user.getPasswordHash();
    }

    public Long getId() {
        return id;
    }

    public Role getRole() {
        return role;
    }

    public boolean isAdmin() {
        return role == Role.ADMIN;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void eraseCredentials() {
        passwordHash = null;
    }
}
