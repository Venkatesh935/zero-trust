package com.zerotrust.service.scanner;

import java.io.IOException;

import com.zerotrust.security.TargetUrlValidator.ValidatedUrl;

/**
 * Performs a single HTTP request (no redirect following) to an already
 * validated destination. Tests replace this with canned responses.
 */
public interface HttpFetcher {

    FetchResult fetch(ValidatedUrl target) throws IOException;
}
