package org.proofsieve.acceptance;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidator;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSSignedData;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;

/** Loopback-only, validation-only DSS bridge for the acceptance suite. */
public final class Bridge {
    private static final int MAX_BODY = 2 * 1024 * 1024;
    private static final int MAX_ARTIFACT = 512 * 1024;
    private static final JsonMapper JSON = JsonMapper.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .build();
    private static final Set<String> COMMON_FIELDS =
        Set.of("version", "nonce", "format", "document", "documentSha256", "certificateSha256");
    private static final Set<String> DETACHED_FIELDS = Set.of("version", "nonce", "format", "document",
        "documentSha256", "certificateSha256", "signature", "signatureSha256");

    private final byte[] authHeader;
    private final Path trustFile;
    private final Path crlFile;

    private Bridge(Path trustFile, Path crlFile) {
        this.trustFile = trustFile;
        this.crlFile = crlFile;
        String bearer = System.getenv("PROOFSIEVE_ACCEPTANCE_DSS_TOKEN");
        if (bearer == null || !bearer.matches("[A-Za-z0-9_-]{32,128}")) {
            throw new IllegalArgumentException("A disposable DSS service bearer is required");
        }
        authHeader = ("Bearer " + bearer).getBytes(StandardCharsets.US_ASCII);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException("Usage: Bridge port tls.p12 trust.pem revocations.crl");
        }
        Bridge bridge = new Bridge(Path.of(args[2]), Path.of(args[3]));
        char[] password = System.getenv("PROOFSIEVE_ACCEPTANCE_STORE_PASSWORD").toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(Path.of(args[1]))) {
            store.load(input, password);
        }
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(store, password);
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(managers.getKeyManagers(), null, null);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", Integer.parseInt(args[0])), 8);
        server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.setExecutor(Executors.newFixedThreadPool(2));
        server.createContext("/validate", bridge::handle);
        server.start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            if (!"/validate".equals(exchange.getRequestURI().toString())
                || !"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
            List<String> auth = exchange.getRequestHeaders().get("Authorization");
            if (auth == null || auth.size() != 1 || !MessageDigest.isEqual(
                authHeader, auth.get(0).getBytes(StandardCharsets.US_ASCII))) {
                exchange.sendResponseHeaders(401, -1);
                return;
            }
            if (!List.of("application/json").equals(exchange.getRequestHeaders().get("Content-Type"))) {
                exchange.sendResponseHeaders(415, -1);
                return;
            }
            byte[] body = exchange.getRequestBody().readNBytes(MAX_BODY + 1);
            if (body.length > MAX_BODY) {
                exchange.sendResponseHeaders(413, -1);
                return;
            }
            final byte[] result;
            try {
                result = JSON.writeValueAsBytes(verify(JSON.readTree(body)));
            } catch (IllegalArgumentException | com.fasterxml.jackson.core.JsonProcessingException malformed) {
                exchange.sendResponseHeaders(400, -1);
                return;
            } catch (Exception failure) {
                // The test operator needs diagnostics on the adapter side only.
                System.err.println("DSS could not complete validation: " + failure.getClass().getSimpleName());
                exchange.sendResponseHeaders(500, -1);
                return;
            }
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, result.length);
            exchange.getResponseBody().write(result);
        }
    }

    private ObjectNode verify(JsonNode request) throws Exception {
        if (request == null || !request.isObject() || !request.path("version").isInt()
            || request.path("version").intValue() != 1) {
            throw new IllegalArgumentException("Invalid request version");
        }
        String format = string(request, "format", "pades|[cxj]ades-detached|cbades-detached|asic-[se]|rfc3161");
        boolean detached = format.endsWith("-detached") || "rfc3161".equals(format);
        Set<String> expected = detached ? DETACHED_FIELDS : COMMON_FIELDS;
        if (request.size() != expected.size() || !expected.stream().allMatch(request::has)) {
            throw new IllegalArgumentException("Unexpected request fields");
        }
        String nonce = string(request, "nonce", "[A-Za-z0-9_-]{16,128}");
        String certHash = string(request, "certificateSha256", "[0-9a-f]{64}");
        String docHash = string(request, "documentSha256", "[0-9a-f]{64}");
        byte[] document = artifact(request, "document", docHash);
        String signatureHash = detached ? string(request, "signatureSha256", "[0-9a-f]{64}") : null;
        byte[] signature = detached ? artifact(request, "signature", signatureHash) : null;

        ObjectNode response = JSON.createObjectNode().put("version", 1).put("nonce", nonce)
            .put("documentSha256", docHash).put("certificateSha256", certHash);
        if (detached) {
            response.put("signatureSha256", signatureHash);
        }
        if ("rfc3161".equals(format)) {
            final DetachedTimestampValidator timestamp;
            var verifier = certificateVerifier();
            try {
                timestamp = AdvancedFormats.timestamp(document, signature, certHash, verifier);
            } catch (Exception malformed) {
                return rejected(response, nonce, "timestamp does not cover the submitted content");
            }
            Reports reports = timestamp.validateDocument();
            var report = reports.getSimpleReport();
            if (report.getTimestampIdList().size() != 1) {
                return rejected(response, nonce, "expected one timestamp");
            }
            Indication indication = report.getIndication(report.getFirstTimestampId());
            return report(response, reports, indication == Indication.PASSED ? Indication.TOTAL_PASSED
                : indication == Indication.FAILED ? Indication.TOTAL_FAILED : indication);
        }
        SignedDocumentValidator validator;
        AdvancedFormats.Prepared advanced = null;
        try {
            if ("cades-detached".equals(format) && new CMSSignedData(signature).getSignedContent() == null) {
                validator = new CMSDocumentValidator(new InMemoryDocument(signature, "signature.p7s"));
                validator.setDetachedContents(List.of(new InMemoryDocument(document, "document.bin")));
            } else if ("pades".equals(format) && coversWholePdf(document)) {
                validator = new PDFDocumentValidator(new InMemoryDocument(document, "document.pdf"));
            } else {
                advanced = AdvancedFormats.prepare(format, document, signature, JSON);
                validator = advanced.validator();
            }
        } catch (Exception malformed) {
            return rejected(response, nonce, "malformed signed document");
        }
        validator.setCertificateVerifier(certificateVerifier());
        Reports reports = validator.validateDocument();
        var report = reports.getSimpleReport();
        String selected = null;
        for (String signatureId : report.getSignatureIdList()) {
            var signatureObject = validator.getSignatureById(signatureId);
            CertificateToken signer = signatureObject == null ? null : signatureObject.getSigningCertificateToken();
            if (signer != null && certHash.equals(sha256(signer.getEncoded()))) {
                if (selected != null) {
                    return rejected(response, nonce, "duplicate selected signer");
                }
                selected = signatureId;
            }
        }
        if (selected == null) {
            return rejected(response, nonce, "signer does not match");
        }
        if (advanced != null) {
            var level = report.getSignatureFormat(selected);
            if (level == null || !level.name().startsWith(advanced.signatureLevel())
                || !advanced.coversContainer(selected)) {
                return rejected(response, nonce, "signature profile or payload coverage does not match");
            }
        }
        return report(response, reports, report.getIndication(selected));
    }

    private static ObjectNode report(ObjectNode response, Reports reports, Indication indication) {
        String verdict = indication == Indication.TOTAL_PASSED ? "passed"
            : indication == Indication.TOTAL_FAILED ? "failed" : "indeterminate";
        return response.put("verdict", verdict).put("reportId",
            "dss-" + sha256(reports.getXmlSimpleReport().getBytes(StandardCharsets.UTF_8)));
    }

    private CommonCertificateVerifier certificateVerifier() throws Exception {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        CommonTrustedCertificateSource trust = new CommonTrustedCertificateSource();
        try (var input = Files.newInputStream(trustFile)) {
            for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(input)) {
                trust.addCertificate(new CertificateToken((X509Certificate) certificate));
            }
        }
        verifier.setTrustedCertSources(trust);
        verifier.setCrlSource(new ExternalResourcesCRLSource(new InMemoryDocument(
            Files.readAllBytes(crlFile), "revocations.crl")));
        return verifier;
    }

    private static boolean coversWholePdf(byte[] document) throws IOException {
        try (var pdf = Loader.loadPDF(document)) {
            List<PDSignature> signatures = pdf.getSignatureDictionaries();
            if (signatures.size() != 1) {
                return false;
            }
            PDSignature signature = signatures.get(0);
            int[] range = signature.getByteRange();
            return PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName().equals(signature.getSubFilter())
                && range.length == 4 && range[0] == 0 && range[1] > 0 && range[2] > range[1]
                && range[3] > 0 && (long) range[2] + range[3] == document.length
                && contentsOnly(document, range[1], range[2]);
        }
    }

    private static boolean contentsOnly(byte[] document, int start, int end) {
        if (end - start < 4 || document[start] != '<' || document[end - 1] != '>') {
            return false;
        }
        int keyEnd = start;
        while (keyEnd > 0 && pdfWhitespace(document[keyEnd - 1])) {
            keyEnd--;
        }
        byte[] key = "/Contents".getBytes(StandardCharsets.US_ASCII);
        if (keyEnd < key.length
            || !new String(document, keyEnd - key.length, key.length, StandardCharsets.US_ASCII).equals("/Contents")) {
            return false;
        }
        int digits = 0;
        for (int i = start + 1; i < end - 1; i++) {
            int value = document[i] & 0xff;
            if (value >= '0' && value <= '9' || value >= 'A' && value <= 'F' || value >= 'a' && value <= 'f') {
                digits++;
            } else if (!pdfWhitespace(value)) {
                return false;
            }
        }
        return digits > 0 && digits % 2 == 0;
    }

    private static boolean pdfWhitespace(int value) {
        return value == 0 || value == 9 || value == 10 || value == 12 || value == 13 || value == 32;
    }

    private static ObjectNode rejected(ObjectNode response, String nonce, String reason) {
        return response.put("verdict", "failed").put("reportId",
            "dss-reject-" + sha256((nonce + ":" + reason).getBytes(StandardCharsets.US_ASCII)));
    }

    private static byte[] artifact(JsonNode request, String field, String expected) {
        String encoded = string(request, field, "[A-Za-z0-9+/=]{1," + (MAX_ARTIFACT * 4 / 3 + 4) + "}");
        byte[] bytes = Base64.getDecoder().decode(encoded);
        if (bytes.length > MAX_ARTIFACT || !Base64.getEncoder().encodeToString(bytes).equals(encoded)
            || !expected.equals(sha256(bytes))) {
            throw new IllegalArgumentException("Invalid artifact");
        }
        return bytes;
    }

    private static String string(JsonNode request, String field, String pattern) {
        JsonNode value = request.path(field);
        if (!value.isTextual() || !value.textValue().matches(pattern)) {
            throw new IllegalArgumentException("Invalid field");
        }
        return value.textValue();
    }

    private static String sha256(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
