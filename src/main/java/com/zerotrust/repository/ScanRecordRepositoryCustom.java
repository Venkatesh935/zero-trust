package com.zerotrust.repository;

import java.time.Instant;

import com.zerotrust.entity.ScanStatus;

public interface ScanRecordRepositoryCustom {

    int failInterruptedScans(ScanStatus running, ScanStatus failed, Instant now, String message);
}
