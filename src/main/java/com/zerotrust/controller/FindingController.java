package com.zerotrust.controller;

import java.time.Instant;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.zerotrust.dto.ApiResponse;
import com.zerotrust.dto.FindingDto;
import com.zerotrust.dto.PageResponse;
import com.zerotrust.entity.FindingCategory;
import com.zerotrust.entity.Severity;
import com.zerotrust.service.FindingService;

@RestController
@RequestMapping("/api/findings")
public class FindingController {

    private final FindingService findingService;

    public FindingController(FindingService findingService) {
        this.findingService = findingService;
    }

    @GetMapping
    public ApiResponse<PageResponse<FindingDto>> search(
            @RequestParam(required = false) Long websiteId,
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) FindingCategory category,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "true") boolean latestOnly,
            @RequestParam(defaultValue = "false") boolean includePassed,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size) {
        return ApiResponse.ok(findingService.search(websiteId, severity, category, from, to, latestOnly,
                includePassed, Math.max(0, page), Math.clamp(size, 1, 100)));
    }

    @GetMapping("/{id}")
    public ApiResponse<FindingDto> get(@PathVariable Long id) {
        return ApiResponse.ok(findingService.get(id));
    }
}
