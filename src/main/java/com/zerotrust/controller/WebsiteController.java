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
import org.springframework.web.bind.annotation.RestController;

import com.zerotrust.dto.ApiResponse;
import com.zerotrust.dto.WebsiteDtos.WebsiteDto;
import com.zerotrust.dto.WebsiteDtos.WebsiteRequest;
import com.zerotrust.service.WebsiteService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/websites")
public class WebsiteController {

    private final WebsiteService websiteService;

    public WebsiteController(WebsiteService websiteService) {
        this.websiteService = websiteService;
    }

    @GetMapping
    public ApiResponse<List<WebsiteDto>> list() {
        return ApiResponse.ok(websiteService.list());
    }

    @GetMapping("/{id}")
    public ApiResponse<WebsiteDto> get(@PathVariable Long id) {
        return ApiResponse.ok(websiteService.get(id));
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<WebsiteDto>> create(@Valid @RequestBody WebsiteRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Website registered.", websiteService.create(request)));
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<WebsiteDto> update(@PathVariable Long id, @Valid @RequestBody WebsiteRequest request) {
        return ApiResponse.ok("Website updated.", websiteService.update(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ApiResponse<Void> delete(@PathVariable Long id) {
        websiteService.delete(id);
        return ApiResponse.ok("Website deleted.", null);
    }
}
