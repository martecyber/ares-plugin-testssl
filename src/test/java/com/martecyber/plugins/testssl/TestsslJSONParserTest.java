package com.martecyber.plugins.testssl;

import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link TestsslJSONParser}: grouping findings by ip:port target, OK-severity findings
 *  being dropped, and the "hostname/ip" combined field format testssl.sh uses for its own
 *  {@code ip} field. */
class TestsslJSONParserTest {

    private final TestsslJSONParser parser = new TestsslJSONParser();

    private ParseResult parse(String json) throws Exception {
        return parser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresAJsonArrayWithSeverityOrFinding() {
        assertTrue(parser.validate("[{\"severity\":\"HIGH\"}]".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("{\"severity\":\"HIGH\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void splitsTheCombinedHostnameSlashIpFieldAndBuildsTheTargetAsset() throws Exception {
        ParseResult result = parse("""
            [{"id":"heartbleed","ip":"example.com/1.2.3.4","port":"443",
              "severity":"HIGH","finding":"Vulnerable to heartbleed"}]
            """);

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals("domain") && a.getIdentifier().equals("example.com")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals("service") && a.getIdentifier().equals("example.com:443")));

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("high", d.getSeverity());
        assertEquals("TLS: heartbleed", d.getTitle());
        assertEquals("example.com:443", d.getAssetIdentifier());
        assertEquals("testssl-heartbleed", d.getSourceTemplateId());
    }

    @Test
    void bareIpTargetIsClassifiedAsAnIpAsset() throws Exception {
        ParseResult result = parse("""
            [{"id":"beast","ip":"1.2.3.4","port":"443","severity":"MEDIUM","finding":"BEAST"}]
            """);
        ParsedAsset asset = result.getAssets().stream()
            .filter(a -> a.getIdentifier().equals("1.2.3.4")).findFirst().orElseThrow();
        assertEquals("ip", asset.getType());
    }

    @Test
    void okSeverityFindingsAreDroppedButTheirTargetAssetStillEmits() throws Exception {
        ParseResult result = parse("""
            [{"id":"cert_chain","ip":"1.2.3.4","port":"443","severity":"OK","finding":"Chain of trust OK"}]
            """);
        assertTrue(result.getDetections().isEmpty());
        assertFalse(result.getAssets().isEmpty());
    }

    @Test
    void cveAndCweAreAppendedToTheDescriptionWhenPresentAndMeaningful() throws Exception {
        ParseResult result = parse("""
            [{"id":"x","ip":"1.2.3.4","port":"443","severity":"HIGH","finding":"Some issue",
              "cve":"CVE-2024-0001","cwe":"CWE-327"}]
            """);
        String desc = result.getDetections().get(0).getDescription();
        assertTrue(desc.contains("CVE: CVE-2024-0001"));
        assertTrue(desc.contains("CWE: CWE-327"));
    }

    @Test
    void placeholderCveDashIsNotAppended() throws Exception {
        ParseResult result = parse("""
            [{"id":"x","ip":"1.2.3.4","port":"443","severity":"HIGH","finding":"Some issue","cve":"-"}]
            """);
        assertFalse(result.getDetections().get(0).getDescription().contains("CVE:"));
    }

    @Test
    void findingsForTheSameTargetAreGroupedUnderOneServiceAssetPair() throws Exception {
        ParseResult result = parse("""
            [{"id":"a","ip":"1.2.3.4","port":"443","severity":"HIGH","finding":"A"},
             {"id":"b","ip":"1.2.3.4","port":"443","severity":"LOW","finding":"B"}]
            """);
        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals("service")).count());
        assertEquals(2, result.getDetections().size());
    }

    @Test
    void entryWithBlankFindingTextIsSkipped() throws Exception {
        ParseResult result = parse("""
            [{"id":"a","ip":"1.2.3.4","port":"443","severity":"HIGH","finding":""}]
            """);
        assertTrue(result.getDetections().isEmpty());
    }

    @Test
    void nonArrayRootProducesAnErrorInsteadOfThrowing() throws Exception {
        ParseResult result = parse("{\"not\":\"an array\"}");
        assertFalse(result.getErrors().isEmpty());
    }
}
