package org.proofsieve.acceptance;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/** Generates cryptographic fixtures with DSS and disposable signing identities. */
public final class Fixtures {
    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        char[] password = System.getenv("PROOFSIEVE_ACCEPTANCE_STORE_PASSWORD").toCharArray();
        byte[] unsignedPdf;
        try (PDDocument pdf = new PDDocument(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            PDPage page = new PDPage();
            pdf.addPage(page);
            try (PDPageContentStream contents = new PDPageContentStream(
                pdf, page, PDPageContentStream.AppendMode.OVERWRITE, false)) {
                contents.beginText();
                contents.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 16);
                contents.newLineAtOffset(48, 700);
                contents.showText("ProofSieve order 1042");
                contents.endText();
            }
            pdf.save(output);
            unsignedPdf = output.toByteArray();
        }
        DSSDocument order = new InMemoryDocument(Files.readAllBytes(directory.resolve("order.json")), "order.json");
        for (String name : Arrays.copyOfRange(args, 1, args.length)) {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(directory.resolve(name + ".p12"))) {
                store.load(input, password);
            }
            String alias = store.aliases().nextElement();
            PrivateKey key = (PrivateKey) store.getKey(alias, password);
            List<CertificateToken> chain = Arrays.stream(store.getCertificateChain(alias))
                .map(cert -> new CertificateToken((X509Certificate) cert)).toList();
            save(directory.resolve(name + ".p7s"), cades(order, key, chain));
            if ("seal".equals(name)) {
                DSSDocument pdf = new InMemoryDocument(unsignedPdf, "order.pdf");
                save(directory.resolve("sealed-order.pdf"), pades(pdf, key, chain));
            }
        }
    }

    private static DSSDocument cades(DSSDocument document, PrivateKey key, List<CertificateToken> chain)
            throws Exception {
        CAdESSignatureParameters parameters = new CAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(chain.get(0));
        parameters.setCertificateChain(chain);
        CAdESService service = new CAdESService(new CommonCertificateVerifier());
        return service.signDocument(document, parameters, sign(service.getDataToSign(document, parameters), key));
    }

    private static DSSDocument pades(DSSDocument document, PrivateKey key, List<CertificateToken> chain)
            throws Exception {
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(chain.get(0));
        parameters.setCertificateChain(chain);
        PAdESService service = new PAdESService(new CommonCertificateVerifier());
        return service.signDocument(document, parameters, sign(service.getDataToSign(document, parameters), key));
    }

    private static SignatureValue sign(ToBeSigned data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(data.getBytes());
        return new SignatureValue(SignatureAlgorithm.RSA_SHA256, signer.sign());
    }

    private static void save(Path destination, DSSDocument document) throws Exception {
        try (var input = document.openStream()) {
            Files.copy(input, destination);
        }
    }
}
