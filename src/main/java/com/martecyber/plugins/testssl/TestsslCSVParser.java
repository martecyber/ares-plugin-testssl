package com.martecyber.plugins.testssl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Parser for testssl.sh CSV export.
 * CSV format: "fqdn/ip","port","proto","id/severity","finding","cve","cwe"
 */
@Component
public class TestsslCSVParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern IP_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    @Override public String getToolId() { return "testssl"; }
    @Override public String getFormatId() { return "csv"; }
    @Override public String getDisplayName() { return "testssl.sh CSV"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".csv"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return (s.contains("fqdn") || s.contains("\"id\"")) && s.contains("finding");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        Set<String> seenAssets = new HashSet<>();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(content), StandardCharsets.UTF_8))) {
            String line = br.readLine(); // skip header
            if (line == null) return result;

            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] cols = parseCsvLine(line);
                if (cols.length < 5) continue;

                String fqdnIp = cols[0].trim();
                String port = cols.length > 1 ? cols[1].trim() : null;
                String idSeverity = cols.length > 3 ? cols[3].trim() : "";
                String finding = cols.length > 4 ? cols[4].trim() : "";
                String cve = cols.length > 5 ? cols[5].trim() : null;
                String cwe = cols.length > 6 ? cols[6].trim() : null;

                if (finding.isBlank()) continue;

                // Parse severity from idSeverity field (format: "id  SEVERITY" or "SEVERITY")
                String severity = extractSeverity(idSeverity);
                if (severity == null) continue; // Skip OK

                String host = fqdnIp.contains("/") ? fqdnIp.split("/")[0] : fqdnIp;
                String target = host + (port != null && !port.isBlank() ? ":" + port : "");

                if (!seenAssets.contains(host)) {
                    seenAssets.add(host);
                    boolean isIp = IP_PATTERN.matcher(host).matches();
                    result.addAsset(new ParsedAsset(host, isIp ? "ip" : "domain", Map.of()));
                }
                if (port != null && !port.isBlank() && !seenAssets.contains(target)) {
                    seenAssets.add(target);
                    result.addAsset(new ParsedAsset(target, "service",
                        Map.of("port", Integer.parseInt(port), "protocol", "TLS")));
                }

                StringBuilder desc = new StringBuilder(finding);
                if (cve != null && !cve.isBlank() && !"-".equals(cve)) desc.append("\nCVE: ").append(cve);
                if (cwe != null && !cwe.isBlank() && !"-".equals(cwe)) desc.append("\nCWE: ").append(cwe);

                String id = idSeverity.replaceAll("(?i)(OK|INFO|WARN|LOW|MEDIUM|HIGH|CRITICAL)\\s*$", "").trim();
                String templateId = "testssl-" + id.toLowerCase().replaceAll("[^a-z0-9_-]", "-");
                if (templateId.length() > 200) templateId = templateId.substring(0, 200);

                String raw;
                try {
                    raw = MAPPER.writeValueAsString(Map.of("id", idSeverity, "finding", finding, "cve", cve != null ? cve : "", "cwe", cwe != null ? cwe : ""));
                } catch (Exception e) { raw = "{}"; }

                String title = "TLS: " + (id.length() > 0 ? id.replace('_', ' ') : finding.substring(0, Math.min(80, finding.length())));
                result.addDetection(new ParsedDetection(title, severity, desc.toString(), target, templateId, raw));
            }
        }
        return result;
    }

    private String extractSeverity(String idSeverity) {
        if (idSeverity == null) return null;
        String upper = idSeverity.toUpperCase();
        if (upper.contains("CRITICAL")) return "critical";
        if (upper.contains("HIGH")) return "high";
        if (upper.contains("MEDIUM")) return "medium";
        if (upper.contains("LOW") || upper.contains("WARN")) return "low";
        if (upper.contains("INFO")) return "info";
        if (upper.contains("OK")) return null;
        return "info";
    }

    private String[] parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    current.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        fields.add(current.toString());
        return fields.toArray(new String[0]);
    }
}
