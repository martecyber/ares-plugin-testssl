package com.martecyber.plugins.testssl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Parser for testssl.sh JSON export.
 * Format: array of objects with id, ip, port, severity, finding, cve, cwe fields.
 */
@Component
public class TestsslJSONParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern IP_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");

    @Override public String getToolId() { return "testssl"; }
    @Override public String getFormatId() { return "json"; }
    @Override public String getDisplayName() { return "testssl.sh JSON"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".json"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8).stripLeading();
        return s.startsWith("[") && (s.contains("\"severity\"") || s.contains("\"finding\""));
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        JsonNode root = MAPPER.readTree(content);
        if (!root.isArray()) { result.addError("Expected JSON array"); return result; }

        // Group by target (ip:port)
        Map<String, String> assetByTarget = new LinkedHashMap<>();
        Map<String, List<JsonNode>> byTarget = new LinkedHashMap<>();

        for (JsonNode node : root) {
            String ip = text(node, "ip"); // format: "domain/ip" or just ip
            String port = text(node, "port");
            if (ip == null) continue;
            // ip field may be "hostname/ip_addr"
            String host = ip.contains("/") ? ip.split("/")[0] : ip;
            String actualIp = ip.contains("/") ? ip.split("/")[1] : ip;
            String target = host + (port != null ? ":" + port : "");
            assetByTarget.computeIfAbsent(target, k -> actualIp);
            byTarget.computeIfAbsent(target, k -> new ArrayList<>()).add(node);
        }

        for (Map.Entry<String, List<JsonNode>> entry : byTarget.entrySet()) {
            String target = entry.getKey();
            String host = target.contains(":") ? target.substring(0, target.lastIndexOf(':')) : target;
            String port = target.contains(":") ? target.substring(target.lastIndexOf(':') + 1) : null;

            // Create assets
            boolean isIp = IP_PATTERN.matcher(host).matches();
            if (!isIp) {
                result.addAsset(new ParsedAsset(host, "domain", Map.of()));
            } else {
                result.addAsset(new ParsedAsset(host, "ip", Map.of()));
            }
            if (port != null) {
                Map<String, Object> svcMeta = new LinkedHashMap<>();
                svcMeta.put("port", Integer.parseInt(port));
                svcMeta.put("protocol", "TLS");
                result.addAsset(new ParsedAsset(target, "service", svcMeta));
            }

            // Process findings
            for (JsonNode node : entry.getValue()) {
                String severity = mapSeverity(text(node, "severity"));
                if ("ok".equals(text(node, "severity")) || severity == null) continue; // skip OK findings

                String id = text(node, "id");
                String finding = text(node, "finding");
                if (finding == null || finding.isBlank()) continue;

                StringBuilder desc = new StringBuilder(finding);
                String cve = text(node, "cve");
                String cwe = text(node, "cwe");
                if (cve != null && !cve.equals("-")) desc.append("\nCVE: ").append(cve);
                if (cwe != null && !cwe.equals("-")) desc.append("\nCWE: ").append(cwe);

                String raw;
                try { raw = MAPPER.writeValueAsString(node); } catch (Exception e) { raw = "{}"; }

                String title = formatTitle(id, finding);
                String templateId = "testssl-" + (id != null ? id.toLowerCase().replaceAll("[^a-z0-9_-]", "-") : "finding");
                result.addDetection(new ParsedDetection(title, severity, desc.toString(), target, templateId, raw));
            }
        }

        return result;
    }

    private String formatTitle(String id, String finding) {
        if (id == null) return finding.length() > 100 ? finding.substring(0, 100) : finding;
        // Pretty-print ID: "heartbleed" → "Heartbleed", "BEAST_CBC_SSL3" → "BEAST CBC SSL3"
        String pretty = id.replace('_', ' ').replace('-', ' ');
        return "TLS: " + pretty;
    }

    private String mapSeverity(String testsslSeverity) {
        if (testsslSeverity == null) return null;
        return switch (testsslSeverity.toUpperCase()) {
            case "CRITICAL" -> "critical";
            case "HIGH" -> "high";
            case "MEDIUM" -> "medium";
            case "LOW", "WARN" -> "low";
            case "INFO" -> "info";
            case "OK" -> null;
            default -> "info";
        };
    }

    private static String text(JsonNode node, String field) {
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && !n.asText().isBlank()) ? n.asText() : null;
    }
}
