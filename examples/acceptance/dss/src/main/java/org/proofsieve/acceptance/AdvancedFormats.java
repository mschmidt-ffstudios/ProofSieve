package org.proofsieve.acceptance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidator;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.validation.COSEDocumentValidator;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.validation.JWSCompactDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/** Constrained format profiles. Proof bytes must cover the submitted payload in full. */
final class AdvancedFormats {
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String FILE = "[A-Za-z0-9][A-Za-z0-9._-]{0,127}";
    private static final int MAX_UNCOMPRESSED = 512 * 1024;
    private static final Set<String> C14N = Set.of(
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2006/12/xml-c14n11");

    record Prepared(SignedDocumentValidator validator, String signatureLevel, Map<String, String> payloads) {
        boolean coversContainer(String signatureId) throws IOException {
            if (payloads.isEmpty()) {
                return true;
            }
            Map<String, String> covered = new HashMap<>();
            for (DSSDocument document : validator.getOriginalDocuments(signatureId)) {
                try (var input = document.openStream()) {
                    if (covered.put(document.getName(), hash(input.readNBytes(MAX_UNCOMPRESSED + 1))) != null) {
                        return false;
                    }
                }
            }
            return covered.equals(payloads);
        }
    }

    static Prepared prepare(String format, byte[] document, byte[] signature, JsonMapper json) throws Exception {
        String filename = "document.bin";
        SignedDocumentValidator validator;
        String level;
        switch (format) {
            case "xades-detached":
                filename = xmlReference(signature);
                validator = new XMLDocumentValidator(new InMemoryDocument(signature, "signature.xml"));
                level = "XAdES_BASELINE_";
                break;
            case "jades-detached":
                String compact = new String(signature, StandardCharsets.US_ASCII);
                if (!compact.matches("[A-Za-z0-9_-]+\\.\\.[A-Za-z0-9_-]+")) {
                    throw new IllegalArgumentException("Expected detached compact JAdES");
                }
                JsonNode header = json.readTree(Base64.getUrlDecoder().decode(compact.split("\\.", -1)[0]));
                if (header == null || !header.isObject() || header.has("sigD") || header.has("x5u")) {
                    throw new IllegalArgumentException("Unsupported JAdES header");
                }
                validator = new JWSCompactDocumentValidator(new InMemoryDocument(signature, "signature.jws"));
                level = "JAdES_BASELINE_";
                break;
            case "cbades-detached":
                var cose = new InMemoryDocument(signature, "signature.cose");
                if (!(COSEParser.fromDocument(cose).parse() instanceof COSESign1 sign1)
                    || sign1.getPayload() != null && !sign1.getPayload().isNull()
                    || sign1.getProtectedHeader().containsKey(COSEHeaderParameter.SIG_D.cbor())
                    || sign1.getUnprotectedHeader().containsKey(COSEHeaderParameter.SIG_D.cbor())
                    || sign1.getProtectedHeader().containsKey(COSEHeaderParameter.X5U.cbor())
                    || sign1.getUnprotectedHeader().containsKey(COSEHeaderParameter.X5U.cbor())) {
                    throw new IllegalArgumentException("Expected detached CB-AdES COSE_Sign1");
                }
                validator = new COSEDocumentValidator(cose);
                level = "CB_AdES_BASELINE_";
                break;
            case "asic-s", "asic-e":
                boolean simple = "asic-s".equals(format);
                var files = containerPayloads(document, simple);
                var container = new ASiCContainerWithCAdESValidator(
                    new InMemoryDocument(document, simple ? "signed.asics" : "signed.asice"));
                if (container.getContainerType() != (simple ? ASiCContainerType.ASiC_S : ASiCContainerType.ASiC_E)) {
                    throw new IllegalArgumentException("ASiC profile mismatch");
                }
                return new Prepared(container, "CAdES_BASELINE_", files);
            default:
                throw new IllegalArgumentException("Unexpected format");
        }
        validator.setDetachedContents(List.of(new InMemoryDocument(document, filename)));
        return new Prepared(validator, level, Map.of());
    }

    static DetachedTimestampValidator timestamp(
        byte[] document, byte[] signature, String certificateHash, CertificateVerifier certificateVerifier)
        throws Exception {
        var validator = new DetachedTimestampValidator(new InMemoryDocument(signature, "timestamp.tst"));
        var data = new InMemoryDocument(document, "document.bin");
        validator.setCertificateVerifier(certificateVerifier);
        validator.setTimestampedData(data);
        TimestampToken token = validator.getTimestamp();
        if (!Set.of(DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512)
                .contains(token.getDigestAlgorithm()) || !token.matchData(data)) {
            throw new IllegalArgumentException("Timestamp imprint does not match");
        }
        var certificates = token.getCertificates().stream()
            .filter(certificate -> certificateHash.equals(hash(certificate.getEncoded()))).toList();
        if (certificates.size() != 1) {
            throw new IllegalArgumentException("Timestamp authority does not match");
        }
        var pinned = new X509CertificateHolder(certificates.get(0).getEncoded());
        token.getTimeStamp().validate(new JcaSimpleSignerInfoVerifierBuilder().build(pinned));
        return validator;
    }

    private static String xmlReference(byte[] signature) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        var xml = factory.newDocumentBuilder().parse(new ByteArrayInputStream(signature));
        var root = xml.getDocumentElement();
        if (!DS.equals(root.getNamespaceURI()) || !"Signature".equals(root.getLocalName())
            || xml.getElementsByTagNameNS(DS, "Signature").getLength() != 1
            || xml.getElementsByTagNameNS(DS, "Manifest").getLength() != 0
            || xml.getElementsByTagNameNS(DS, "RetrievalMethod").getLength() != 0) {
            throw new IllegalArgumentException("Unsupported XAdES signature structure");
        }
        var signedInfo = xml.getElementsByTagNameNS(DS, "SignedInfo");
        if (signedInfo.getLength() != 1 || signedInfo.item(0).getParentNode() != root) {
            throw new IllegalArgumentException("Expected one SignedInfo under the XAdES signature");
        }
        var transforms = xml.getElementsByTagNameNS(DS, "Transform");
        for (int i = 0; i < transforms.getLength(); i++) {
            if (!C14N.contains(((Element) transforms.item(i)).getAttribute("Algorithm"))) {
                throw new IllegalArgumentException("Unsupported XAdES transform");
            }
        }
        var references = xml.getElementsByTagNameNS(DS, "Reference");
        String payload = null;
        int properties = 0;
        for (int i = 0; i < references.getLength(); i++) {
            Element reference = (Element) references.item(i);
            if (reference.getParentNode() != signedInfo.item(0)) {
                throw new IllegalArgumentException("XAdES references must be covered by SignedInfo");
            }
            String uri = reference.getAttribute("URI");
            if (uri.startsWith("#") && uri.substring(1).matches(FILE)
                && "http://uri.etsi.org/01903#SignedProperties".equals(reference.getAttribute("Type"))) {
                properties++;
            } else if (payload == null && uri.matches(FILE)
                && reference.getElementsByTagNameNS(DS, "Transform").getLength() == 0) {
                payload = uri;
            } else {
                throw new IllegalArgumentException("Unsupported XAdES data reference");
            }
        }
        if (payload == null || properties != 1) {
            throw new IllegalArgumentException("Expected one detached XAdES payload");
        }
        return payload;
    }

    private static Map<String, String> containerPayloads(byte[] bytes, boolean simple) throws IOException {
        var expectedType = simple ? "application/vnd.etsi.asic-s+zip" : "application/vnd.etsi.asic-e+zip";
        if (bytes.length < 22) {
            throw new IllegalArgumentException("Invalid ASiC container");
        }
        var zip = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int end = bytes.length - 22;
        int count = Short.toUnsignedInt(zip.getShort(end + 10));
        if (zip.getInt(0) != 0x04034b50 || zip.getInt(end) != 0x06054b50 || zip.getInt(end + 4) != 0
            || zip.getShort(end + 8) != count || zip.getShort(end + 20) != 0 || count < 2 || count > 32
            || (long) zip.getInt(end + 12) + zip.getInt(end + 16) != end) {
            throw new IllegalArgumentException("Unsupported ASiC ZIP structure");
        }
        var names = new HashSet<String>();
        var entries = new HashMap<String, String>();
        var payloads = new HashMap<String, String>();
        int remaining = MAX_UNCOMPRESSED;
        boolean typeFound = false;
        try (var input = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            for (var entry = input.getNextEntry(); entry != null; entry = input.getNextEntry()) {
                String name = entry.getName();
                if (entry.isDirectory() || !names.add(name.toLowerCase(Locale.ROOT)) || names.size() > count) {
                    throw new IllegalArgumentException("Unsupported ASiC ZIP entries");
                }
                byte[] content = input.readNBytes(remaining + 1);
                remaining -= content.length;
                if (remaining < 0) {
                    throw new IllegalArgumentException("Expanded ASiC exceeds limit");
                }
                String digest = hash(content);
                entries.put(name, digest);
                if (name.equals("mimetype")) {
                    typeFound = expectedType.equals(new String(content, StandardCharsets.US_ASCII));
                } else if (name.matches(FILE)) {
                    payloads.put(name, digest);
                } else if (!name.matches("META-INF/(?:signature[A-Za-z0-9._-]*\\.p7s|ASiCManifest[A-Za-z0-9._-]*\\.xml)")) {
                    throw new IllegalArgumentException("Unsupported ASiC metadata");
                }
            }
        }
        if (!typeFound || names.size() != count || payloads.isEmpty() || simple && payloads.size() != 1
            || !centralDirectoryMatches(bytes, entries)) {
            throw new IllegalArgumentException("ASiC payload or type mismatch");
        }
        return payloads;
    }

    private static boolean centralDirectoryMatches(byte[] bytes, Map<String, String> entries) throws IOException {
        // DSS reads the local ZIP records. Other ZIP consumers may read the central directory.
        var file = Files.createTempFile("proofsieve-asic-", ".zip");
        try {
            Files.write(file, bytes);
            try (var zip = new ZipFile(file.toFile())) {
                if (zip.size() != entries.size()) {
                    return false;
                }
                var names = new HashSet<String>();
                int remaining = MAX_UNCOMPRESSED;
                var records = zip.entries();
                while (records.hasMoreElements()) {
                    var entry = records.nextElement();
                    String name = entry.getName();
                    if (!entries.containsKey(name) || !names.add(name)) {
                        return false;
                    }
                    try (var input = zip.getInputStream(entry)) {
                        byte[] content = input.readNBytes(remaining + 1);
                        remaining -= content.length;
                        if (remaining < 0 || !entries.get(name).equals(hash(content))) {
                            return false;
                        }
                    }
                }
                return true;
            }
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String hash(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private AdvancedFormats() {}
}
