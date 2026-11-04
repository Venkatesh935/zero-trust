package com.zerotrust.service;

import org.springframework.stereotype.Service;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.dto.SettingsDto;
import com.zerotrust.dto.SettingsDto.SettingsUpdateRequest;
import com.zerotrust.entity.AppSetting;
import com.zerotrust.entity.AuditAction;
import com.zerotrust.repository.AppSettingRepository;

@Service
public class SettingsService {

    static final String REGISTRATION_ENABLED = "registration.enabled";

    private final AppSettingRepository repository;
    private final ZeroTrustProperties properties;
    private final AuditService auditService;

    public SettingsService(AppSettingRepository repository, ZeroTrustProperties properties, AuditService auditService) {
        this.repository = repository;
        this.properties = properties;
        this.auditService = auditService;
    }

    public boolean isRegistrationEnabled() {
        return repository.findById(REGISTRATION_ENABLED).map(s -> Boolean.parseBoolean(s.getValue())).orElse(true);
    }

    public SettingsDto get() {
        ZeroTrustProperties.Scanner scanner = properties.getScanner();
        ZeroTrustProperties.Monitoring monitoring = properties.getMonitoring();
        return new SettingsDto(isRegistrationEnabled(), scanner.getConnectTimeoutMs(), scanner.getReadTimeoutMs(),
                scanner.getMaxRedirects(), scanner.getMaxHeaderBytes(), scanner.getAllowedPorts(),
                scanner.getManualScanCooldownSeconds(), monitoring.getMinIntervalMinutes(),
                monitoring.getMaxIntervalMinutes(), properties.getSecurity().getMaxFailedLogins(),
                properties.getSecurity().getLockoutMinutes());
    }

    public SettingsDto update(SettingsUpdateRequest request) {
        if (request.registrationEnabled() != null) {
            AppSetting setting = repository.findById(REGISTRATION_ENABLED)
                    .orElseGet(() -> new AppSetting(REGISTRATION_ENABLED, "true"));
            setting.setValue(String.valueOf(request.registrationEnabled()));
            repository.save(setting);
            auditService.log(AuditAction.SETTINGS_UPDATED,
                    "Self-registration " + (request.registrationEnabled() ? "enabled" : "disabled"), null);
        }
        return get();
    }
}
