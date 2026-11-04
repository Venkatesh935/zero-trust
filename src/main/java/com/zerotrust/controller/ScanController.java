package com.zerotrust.controller;

import java.time.Instant;
import java.util.List;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.zerotrust.dto.ApiResponse;
import com.zerotrust.dto.FindingDto;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.dto.ScanRequest;
import com.zerotrust.dto.ScanResponse;
import com.zerotrust.dto.ScanSummaryDto;
import com.zerotrust.entity.ScanStatus;
import com.zerotrust.service.ScanService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    /** Runs a passive scan of a registered website and returns the full result. */
    @PostMapping
    public ResponseEntity<ApiResponse<ScanResponse>> start(@Valid @RequestBody ScanRequest request) {
        ScanResponse result = scanService.startManualScan(request.websiteId());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok("Scan finished.", result));
    }

    @GetMapping
    public ApiResponse<PageResponse<ScanSummaryDto>> list(
            @RequestParam(required = false) Long websiteId,
            @RequestParam(required = false) ScanStatus status,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ApiResponse.ok(scanService.listScans(websiteId, status, from, to,
                Math.max(0, page), Math.clamp(size, 1, 100)));
    }

    @GetMapping("/{id}")
    public ApiResponse<ScanResponse> get(@PathVariable Long id) {
        return ApiResponse.ok(scanService.getScan(id));
    }

    @GetMapping("/{id}/findings")
    public ApiResponse<List<FindingDto>> findings(@PathVariable Long id) {
        return ApiResponse.ok(scanService.getScanFindings(id));
    }
}
