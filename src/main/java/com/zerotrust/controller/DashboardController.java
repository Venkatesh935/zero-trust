package com.zerotrust.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.zerotrust.dto.ApiResponse;
import com.zerotrust.dto.DashboardDtos.DashboardSummary;
import com.zerotrust.dto.DashboardDtos.RiskDistribution;
import com.zerotrust.dto.ScanSummaryDto;
import com.zerotrust.service.DashboardService;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final DashboardService dashboardService;

    public DashboardController(DashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    @GetMapping("/summary")
    public ApiResponse<DashboardSummary> summary() {
        return ApiResponse.ok(dashboardService.summary());
    }

    @GetMapping("/recent-scans")
    public ApiResponse<List<ScanSummaryDto>> recentScans(@RequestParam(defaultValue = "8") int limit) {
        return ApiResponse.ok(dashboardService.recentScans(Math.clamp(limit, 1, 50)));
    }

    @GetMapping("/risk-distribution")
    public ApiResponse<RiskDistribution> riskDistribution() {
        return ApiResponse.ok(dashboardService.riskDistribution());
    }
}
