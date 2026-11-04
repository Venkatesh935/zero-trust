package com.zerotrust.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.zerotrust.dto.ApiResponse;
import com.zerotrust.dto.SettingsDto;
import com.zerotrust.dto.SettingsDto.SettingsUpdateRequest;
import com.zerotrust.service.SettingsService;

@RestController
@RequestMapping("/api/settings")
public class SettingsController {

    private final SettingsService settingsService;

    public SettingsController(SettingsService settingsService) {
        this.settingsService = settingsService;
    }

    @GetMapping
    public ApiResponse<SettingsDto> get() {
        return ApiResponse.ok(settingsService.get());
    }

    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<SettingsDto> update(@RequestBody SettingsUpdateRequest request) {
        return ApiResponse.ok("Settings saved.", settingsService.update(request));
    }
}
