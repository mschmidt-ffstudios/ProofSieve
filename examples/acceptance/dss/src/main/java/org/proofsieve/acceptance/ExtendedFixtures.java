package org.proofsieve.acceptance;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/** Generates the advanced format fixtures with a disposable signer and timestamp authority. */
public final class ExtendedFixtures {
    private record Identity(PrivateKey key, List<CertificateToken> chain) {
        static Identity load(Path path, char[] password) throws Exception {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(path)) {
                store.load(input, password);
            }
            String alias = store.aliases().nextElement();
            List<CertificateToken> chain = Arrays.stream(store.getCertificateChain(alias))
                .map(cert -> new CertificateToken((X509Certificate) cert)).toList();
            return new Identity((PrivateKey) store.getKey(alias, password), chain);
        }

        void configure(AbstractSignatureParameters<?> parameters, SignatureLevel level) {
            parameters.setSignatureLevel(level);
            parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(chain.get(0));
            parameters.setCertificateChain(chain);
        }

        SignatureValue sign(ToBeSigned data) throws Exception {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key);
            signer.update(data.getBytes());
            return new SignatureValue(SignatureAlgorithm.RSA_SHA256, signer.sign());
        }
    }

    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]);
        char[] password = System.getenv("PROOFSIEVE_ACCEPTANCE_STORE_PASSWORD").toCharArray();
        Identity signer = Identity.load(directory.resolve("signer.p12"), password);
        Identity tsa = Identity.load(directory.resolve("tsa.p12"), password);
        byte[] payload = Files.readAllBytes(directory.resolve("order.json"));
        DSSDocument order = new InMemoryDocument(payload, "order.json");

        var xml = new XAdESSignatureParameters();
        signer.configure(xml, SignatureLevel.XAdES_BASELINE_B);
        var xades = new XAdESService(new CommonCertificateVerifier());
        save(directory.resolve("xades.xml"), xades.signDocument(order, xml, signer.sign(xades.getDataToSign(order, xml))));

        var json = new JAdESSignatureParameters();
        signer.configure(json, SignatureLevel.JAdES_BASELINE_B);
        json.setIncludeCertificateChain(true);
        json.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
        json.setSigDMechanism(SigDMechanism.NO_SIG_D);
        var jades = new JAdESService(new CommonCertificateVerifier());
        save(directory.resolve("jades.jws"), jades.signDocument(order, json, signer.sign(jades.getDataToSign(order, json))));

        var cbor = new CBAdESSignatureParameters();
        signer.configure(cbor, SignatureLevel.CB_AdES_BASELINE_B);
        cbor.setIncludeCertificateChain(true);
        cbor.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        cbor.setSigDMechanism(SigDMechanism.NO_SIG_D);
        var cbades = new CBAdESService(new CommonCertificateVerifier());
        save(directory.resolve("cbades.cose"), cbades.signDocument(
            order, cbor, signer.sign(cbades.getDataToSign(order, cbor))));

        var asic = new ASiCWithCAdESService(new CommonCertificateVerifier());
        for (boolean simple : new boolean[] { true, false }) {
            var parameters = new ASiCWithCAdESSignatureParameters();
            signer.configure(parameters, SignatureLevel.CAdES_BASELINE_B);
            parameters.aSiC().setContainerType(simple ? ASiCContainerType.ASiC_S : ASiCContainerType.ASiC_E);
            parameters.aSiC().setZipComment(false);
            List<DSSDocument> contents = simple ? List.of(order)
                : List.of(order, new InMemoryDocument("EUR".getBytes(java.nio.charset.StandardCharsets.UTF_8), "currency.txt"));
            save(directory.resolve(simple ? "signed.asics" : "signed.asice"),
                asic.signDocument(contents, parameters, signer.sign(asic.getDataToSign(contents, parameters))));
        }

        var digests = new JcaDigestCalculatorProviderBuilder().build();
        var timestamp = new TimeStampTokenGenerator(new JcaSignerInfoGeneratorBuilder(digests).build(
            new JcaContentSignerBuilder("SHA256withRSA").build(tsa.key()), tsa.chain().get(0).getCertificate()),
            digests.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
            new ASN1ObjectIdentifier("1.3.6.1.4.1.55555.1"));
        timestamp.addCertificates(new JcaCertStore(tsa.chain().stream().map(CertificateToken::getCertificate).toList()));
        var request = new TimeStampRequestGenerator();
        request.setCertReq(true);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(payload);
        Files.write(directory.resolve("timestamp.tst"), timestamp.generate(
            request.generate(TSPAlgorithms.SHA256, hash), BigInteger.ONE, new Date()).getEncoded());
    }

    private static void save(Path destination, DSSDocument document) throws Exception {
        try (var input = document.openStream()) {
            Files.copy(input, destination);
        }
    }
}
