package com.zerotrust.config;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.zerotrust.entity.AppUser;
import com.zerotrust.entity.Role;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.repository.AppUserRepository;
import com.zerotrust.repository.ScanRecordRepository;
import com.zerotrust.util.PasswordPolicy;

/**
 * First-start setup. Creates the initial administrator only when no users
 * exist. The password comes from the ZT_ADMIN_PASSWORD environment variable;
 * if it is missing or weak, a random password is generated and printed once
 * to the console. No password is hard-coded in source code.
 */
@Component
public class DataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final AppUserRepository users;
    private final ScanRecordRepository scans;
    private final PasswordEncoder passwordEncoder;
    private final ZeroTrustProperties properties;

    public DataInitializer(AppUserRepository users, ScanRecordRepository scans, PasswordEncoder passwordEncoder,
            ZeroTrustProperties properties) {
        this.users = users;
        this.scans = scans;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) {
        int interrupted = scans.failInterruptedScans(ScanStatus.RUNNING, ScanStatus.FAILED, Instant.now(),
                "Scan interrupted by application restart.");
        if (interrupted > 0) {
            log.info("Marked {} interrupted scan(s) as FAILED", interrupted);
        }

        if (users.count() > 0) {
            return;
        }
        String username = properties.getAdmin().getUsername();
        String password = properties.getAdmin().getPassword();
        boolean generated = false;
        if (password == null || password.isBlank()) {
            password = PasswordPolicy.generate(16);
            generated = true;
        } else if (!PasswordPolicy.isStrong(password, username)) {
            log.warn("ZT_ADMIN_PASSWORD does not meet the password policy ({}). A random password will be used instead.",
                    PasswordPolicy.DESCRIPTION);
            password = PasswordPolicy.generate(16);
            generated = true;
        }

        AppUser admin = new AppUser();
        admin.setUsername(username);
        admin.setFullName("System Administrator");
        admin.setPasswordHash(passwordEncoder.encode(password));
        admin.setRole(Role.ADMIN);
        admin.setEnabled(true);
        users.save(admin);

        if (generated) {
            log.warn("""

                    ================================================================
                     Initial administrator account created
                       Username: {}
                       Password: {}
                     This password is shown only once. Sign in and change it under
                     Settings, or set ZT_ADMIN_PASSWORD before the first start.
                    ================================================================""", username, password);
        } else {
            log.info("Initial administrator '{}' created from ZT_ADMIN_PASSWORD.", username);
        }
    }
}
