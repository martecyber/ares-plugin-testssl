package com.martecyber.plugins.testssl;

import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link TestsslCSVParser}: severity extraction from the combined "id  SEVERITY" column,
 *  the OK-row skip, and asset/service emission from the fqdn/ip + port columns. */
class TestsslCSVParserTest {

    private final TestsslCSVParser parser = new TestsslCSVParser();

    private ParseResult parse(String csv) throws Exception {
        return parser.parse(csv.getBytes(StandardCharsets.UTF_8));
    }

    private static final String HEADER = "fqdn/ip,port,proto,id,finding,cve,cwe\n";

    @Test
    void validateRequiresFqdnOrIdColumnPlusFinding() {
        assertTrue(parser.validate((HEADER).getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("a,b,c\n".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void extractsSeverityFromTheTrailingWordOfTheIdColumn() throws Exception {
        ParseResult result = parse(HEADER + "example.com/1.2.3.4,443,tcp,heartbleed HIGH,Vulnerable to heartbleed,,\n");

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("high", d.getSeverity());
        assertEquals("TLS: heartbleed", d.getTitle());
        assertEquals("example.com:443", d.getAssetIdentifier());
    }

    @Test
    void okRowsAreSkipped() throws Exception {
        ParseResult result = parse(HEADER + "1.2.3.4,443,tcp,cert_chain OK,Chain of trust OK,,\n");
        assertTrue(result.getDetections().isEmpty());
    }

    @Test
    void emitsIpAndServiceAssetsFromTheFqdnAndPortColumns() throws Exception {
        ParseResult result = parse(HEADER + "1.2.3.4,443,tcp,beast MEDIUM,BEAST vulnerability,,\n");

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals("ip") && a.getIdentifier().equals("1.2.3.4")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals("service") && a.getIdentifier().equals("1.2.3.4:443")));
    }

    @Test
    void cveAndCweColumnsAreAppendedToTheDescriptionUnlessPlaceholderDash() throws Exception {
        ParseResult result = parse(HEADER + "1.2.3.4,443,tcp,x HIGH,Some issue,CVE-2024-0001,-\n");
        String desc = result.getDetections().get(0).getDescription();
        assertTrue(desc.contains("CVE: CVE-2024-0001"));
        assertFalse(desc.contains("CWE:"));
    }

    @Test
    void rowsWithTooFewColumnsAreSkippedWithoutFailingTheWholeFile() throws Exception {
        ParseResult result = parse(HEADER + "only,two\n" + "1.2.3.4,443,tcp,x HIGH,Real finding,,\n");
        assertEquals(1, result.getDetections().size());
    }

    @Test
    void quotedFieldsWithEmbeddedCommasAreHandledByTheLineTokenizer() throws Exception {
        ParseResult result = parse(HEADER + "1.2.3.4,443,tcp,x HIGH,\"Finding, with a comma\",,\n");
        assertEquals("Finding, with a comma", result.getDetections().get(0).getDescription());
    }

    @Test
    void headerOnlyContentProducesNoDetections() throws Exception {
        ParseResult result = parse(HEADER);
        assertTrue(result.getDetections().isEmpty());
    }
}
