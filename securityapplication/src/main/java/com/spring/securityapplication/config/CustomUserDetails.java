package com.spring.securityapplication.config;


import com.spring.securityapplication.entity.UserCredential;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class CustomUserDetails implements UserDetails {

    private String username;
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(UserCredential userCredential) {
        this.username = userCredential.getUserName();
        this.password = userCredential.getPassword();
        this.authorities = userCredential.getRoles().stream()
                .map(role -> "ROLE_" + role) // Prefix roles with "ROLE_"
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
