package com.zerotrust.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.zerotrust.config.ZeroTrustProperties;
import com.zerotrust.service.MonitoringService;

/**
 * Periodically runs due monitoring checks. Each cycle handles at most
 * {@code zerotrust.monitoring.max-checks-per-cycle} websites, and each website
 * is checked no more often than its configured interval (minimum 5 minutes),
 * which keeps request volume low.
 */
@Component
public class MonitoringScheduler {

    private static final Logger log = LoggerFactory.getLogger(MonitoringScheduler.class);

    private final MonitoringService monitoringService;
    private final ZeroTrustProperties properties;

    public MonitoringScheduler(MonitoringService monitoringService, ZeroTrustProperties properties) {
        this.monitoringService = monitoringService;
        this.properties = properties;
    }

    @Scheduled(fixedDelayString = "${zerotrust.monitoring.poll-interval-ms:60000}",
            initialDelayString = "${zerotrust.monitoring.initial-delay-ms:30000}")
    public void runDueChecks() {
        if (!properties.getMonitoring().isSchedulerEnabled()) {
            return;
        }
        int done = monitoringService.runDueChecks();
        if (done > 0) {
            log.info("Monitoring cycle completed {} check(s)", done);
        }
    }
}
