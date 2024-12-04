package com.bank.backend.domain.services;

import com.bank.backend.application.exception.DuplicateResourceException;
import com.bank.backend.application.exception.InvalidCredentialsException;
import com.bank.backend.domain.enums.UserStatus;
import com.bank.backend.domain.model.SysUser;
import com.bank.backend.domain.model.UserAuthentication;
import com.bank.backend.domain.providers.IdentityProvider;
import com.bank.backend.domain.services.security.JwtService;
import com.bank.backend.domain.services.security.OtpService;
import com.bank.backend.domain.services.security.SysUserDetailsService;
import com.bank.backend.persistance.repository.SysUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class IdmService {
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final SysUserDetailsService sysUserDetailsService;
    private final SysUserRepository sysUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final IdentityProvider identityProvider;

    public SysUser register(SysUser user) {
        validateUserInfo(user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        fillUpMissingInfo(user);
        return sysUserRepository.save(user);
    }
    private void validateUserInfo(SysUser user) {

        if(sysUserRepository.isUsernameAlreadyExists(user.getUsername())) {
            throw new DuplicateResourceException("Username already exists");
        }
    }


    private void fillUpMissingInfo(SysUser user) {
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        user.setStatue(UserStatus.ACTIVE);


    }

    public UserAuthentication login(UserAuthentication userAuthentication) {
        Authentication authentication = getAuthenticationStatus(userAuthentication);
        if(authentication.isAuthenticated()) {
            updateSecurityContextHolder(authentication);
            return buildUserAuthentication(userAuthentication);
        }

        throw new InvalidCredentialsException("Bad credentials, username or password are incorrect");
    }

    private static void updateSecurityContextHolder(Authentication authentication) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private UserAuthentication buildUserAuthentication(UserAuthentication userAuthentication) {
        UserDetails user = sysUserDetailsService.loadUserByUsername(userAuthentication.getUsername());
        String token = jwtService.generateToken(user);
        userAuthentication.setToken(token);
        return userAuthentication;
    }

    private Authentication getAuthenticationStatus(UserAuthentication endUserAuthentication) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        endUserAuthentication.getUsername(),
                        endUserAuthentication.getPassword()
                )
        );
    }


    public SysUser getUserByUsername(String username) {
        return sysUserRepository.findByUsername(username);
    }

    public void obtainOtp() throws NoSuchAlgorithmException, InvalidKeyException {
        SysUser user = identityProvider.currentIdentity();
        String otp = otpService.generateOtp(user.getUsername());
        // TODO : send otp to email
        log.info("Generated OTP: {}", otp);
    }


    public Boolean verifyOtp(String otp) throws NoSuchAlgorithmException, InvalidKeyException {
        return otpService.verifyOtp(otp, identityProvider.currentIdentity().getUsername());
    }

    public Boolean validateToken(HttpServletRequest request) {
        UserDetails user = identityProvider.currentIdentityDetails();
        return jwtService.isTokenValid(jwtService.extractToken(request), user);
    }
}
