package com.zerotrust.service.scanner;

import static com.zerotrust.entity.FindingCategory.INFORMATION_DISCLOSURE;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import com.zerotrust.entity.Severity;

/**
 * Identifies response headers that reveal server technology. This is
 * informational: revealing a technology is not proof of a vulnerability.
 */
public class DisclosureAnalyzer {

    private static final Pattern VERSION = Pattern.compile("\\d+\\.\\d+");
    private static final String NOTE = " Technology disclosure is not a vulnerability by itself, but it helps "
            + "attackers fingerprint the server and look up version-specific weaknesses.";

    public List<FindingDraft> analyze(ResponseHeaders headers) {
        List<FindingDraft> results = new ArrayList<>();

        String server = headers.first("Server");
        if (server == null) {
            results.add(FindingDraft.pass(INFORMATION_DISCLOSURE, "DISCLOSURE_SERVER", "Server header not disclosed",
                    "The response does not include a Server header.", "Not present"));
        } else if (VERSION.matcher(server).find()) {
            results.add(FindingDraft.fail(INFORMATION_DISCLOSURE, "DISCLOSURE_SERVER", Severity.LOW,
                    "Server header reveals software version",
                    "The Server header includes a version number." + NOTE, "Server: " + server,
                    "Configure the web server to omit version details (e.g. nginx server_tokens off; Apache ServerTokens Prod)."));
        } else {
            results.add(FindingDraft.fail(INFORMATION_DISCLOSURE, "DISCLOSURE_SERVER", Severity.INFORMATIONAL,
                    "Server header reveals technology",
                    "The Server header names the server software without a version." + NOTE, "Server: " + server,
                    "Optionally remove or genericize the Server header."));
        }

        String poweredBy = headers.first("X-Powered-By");
        if (poweredBy == null) {
            results.add(FindingDraft.pass(INFORMATION_DISCLOSURE, "DISCLOSURE_POWERED_BY",
                    "X-Powered-By header not disclosed", "The response does not include X-Powered-By.", "Not present"));
        } else {
            results.add(FindingDraft.fail(INFORMATION_DISCLOSURE, "DISCLOSURE_POWERED_BY", Severity.LOW,
                    "X-Powered-By header reveals technology",
                    "X-Powered-By identifies the application framework or language." + NOTE,
                    "X-Powered-By: " + poweredBy, "Remove the X-Powered-By header in the application or server configuration."));
        }

        for (String name : List.of("X-AspNet-Version", "X-AspNetMvc-Version")) {
            String value = headers.first(name);
            if (value != null) {
                results.add(FindingDraft.fail(INFORMATION_DISCLOSURE, "DISCLOSURE_" + name.toUpperCase(java.util.Locale.ROOT).replace('-', '_'),
                        Severity.LOW, name + " header reveals framework version",
                        "The header discloses the exact framework version." + NOTE, name + ": " + value,
                        "Disable the " + name + " header in the application configuration."));
            }
        }
        String generator = headers.first("X-Generator");
        if (generator != null) {
            results.add(FindingDraft.fail(INFORMATION_DISCLOSURE, "DISCLOSURE_GENERATOR", Severity.INFORMATIONAL,
                    "X-Generator header reveals CMS", "The header names the content management system." + NOTE,
                    "X-Generator: " + generator, "Remove the X-Generator header if it is not required."));
        }
        return results;
    }
}
