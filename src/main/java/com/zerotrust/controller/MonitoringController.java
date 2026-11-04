package com.zerotrust.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.zerotrust.dto.ApiResponse;
import com.zerotrust.dto.MonitoringDtos.MonitoringDto;
import com.zerotrust.dto.MonitoringDtos.MonitoringEventDto;
import com.zerotrust.dto.MonitoringDtos.MonitoringRequest;
import com.zerotrust.dto.MonitoringDtos.MonitoringUpdateRequest;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.service.MonitoringService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/monitoring")
public class MonitoringController {

    private final MonitoringService monitoringService;

    public MonitoringController(MonitoringService monitoringService) {
        this.monitoringService = monitoringService;
    }

    @GetMapping
    public ApiResponse<List<MonitoringDto>> list() {
        return ApiResponse.ok(monitoringService.list());
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<MonitoringDto>> create(@Valid @RequestBody MonitoringRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Monitoring configured.", monitoringService.create(request)));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<MonitoringDto> update(@PathVariable Long id, @RequestBody MonitoringUpdateRequest request) {
        return ApiResponse.ok("Monitoring updated.", monitoringService.update(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<Void> delete(@PathVariable Long id) {
        monitoringService.delete(id);
        return ApiResponse.ok("Monitoring removed.", null);
    }

    @GetMapping("/{id}/history")
    public ApiResponse<PageResponse<MonitoringEventDto>> history(@PathVariable Long id,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "20") int size) {
        return ApiResponse.ok(monitoringService.history(id, Math.max(0, page), Math.clamp(size, 1, 100)));
    }

    /** Runs a monitoring check immediately instead of waiting for the schedule. */
    @PostMapping("/{id}/run")
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<MonitoringEventDto> runNow(@PathVariable Long id) {
        return ApiResponse.ok("Monitoring check completed.", monitoringService.runNow(id));
    }
}
