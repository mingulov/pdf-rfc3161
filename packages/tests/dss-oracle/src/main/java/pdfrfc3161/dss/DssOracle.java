package pdfrfc3161.dss;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

/**
 * Validates one PDF with EU DSS and prints a JSON verdict for the PAdES
 * conformance harness, which owns every expectation. Verdicts are data:
 * an invalid or unsigned PDF still exits 0. A nonzero exit means the
 * harness itself failed (bad arguments, unreadable files, DSS errors).
 */
public final class DssOracle {
    private DssOracle() {
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (UsageException usage) {
            System.err.println("DSS-ORACLE-USAGE " + usage.getMessage());
            System.exit(2);
        } catch (Exception failure) {
            System.err.println("DSS-ORACLE-ERROR " + failure);
            System.exit(1);
        }
    }

    private static void run(String[] args) throws Exception {
        if (args.length == 1 && "--version".equals(args[0])) {
            System.out.println(dssVersion());
            return;
        }
        Path pdfPath = flagValue(args, "--pdf");
        Path trustPath = flagValue(args, "--trust");
        if (pdfPath == null || trustPath == null) {
            throw new UsageException("expected --pdf <path> --trust <pem-or-der>");
        }
        System.out.println(validate(pdfPath, trustPath));
    }

    private static Path flagValue(String[] args, String flag) {
        for (int index = 0; index + 1 < args.length; index++) {
            if (flag.equals(args[index])) {
                return Paths.get(args[index + 1]);
            }
        }
        return null;
    }

    private static String dssVersion() throws IOException {
        try (InputStream in = DssOracle.class.getResourceAsStream("/dss-oracle.properties")) {
            if (in == null) {
                throw new IllegalStateException("dss-oracle.properties is missing from the jar");
            }
            Properties properties = new Properties();
            properties.load(in);
            String version = properties.getProperty("dss.version");
            if (version == null || version.isEmpty() || version.indexOf('$') >= 0) {
                throw new IllegalStateException("dss.version was not filtered at build time");
            }
            return version;
        }
    }

    private static String validate(Path pdfPath, Path trustPath) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate trustCert;
        try (InputStream in = Files.newInputStream(trustPath)) {
            trustCert = (X509Certificate) factory.generateCertificate(in);
        }
        CommonTrustedCertificateSource trustedSource = new CommonTrustedCertificateSource();
        trustedSource.addCertificate(new CertificateToken(trustCert));
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.addTrustedCertSources(trustedSource);

        DSSDocument document = new FileDocument(pdfPath.toFile());
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);
        validator.setCertificateVerifier(verifier);
        Reports reports = validator.validateDocument();

        List<String> signatures = reports.getSimpleReport().getSignatureIdList();
        List<String> timestamps = reports.getSimpleReport().getTimestampIdList();
        StringBuilder json = new StringBuilder("{");
        json.append("\"tool\":\"dss-oracle\",");
        json.append("\"dss\":").append(jsonString(dssVersion())).append(",");
        json.append("\"pdf\":").append(jsonString(pdfPath.toString())).append(",");
        json.append("\"signatures\":[");
        for (int index = 0; index < signatures.size(); index++) {
            if (index > 0) {
                json.append(",");
            }
            json.append(jsonString(signatures.get(index)));
        }
        json.append("],\"timestamps\":[");
        for (int index = 0; index < timestamps.size(); index++) {
            if (index > 0) {
                json.append(",");
            }
            String id = timestamps.get(index);
            Indication indication = reports.getSimpleReport().getIndication(id);
            SubIndication subIndication = reports.getSimpleReport().getSubIndication(id);
            json.append("{\"id\":").append(jsonString(id));
            json.append(",\"indication\":").append(jsonString(indication.name()));
            json.append(",\"subIndication\":")
                    .append(subIndication == null ? "null" : jsonString(subIndication.name()))
                    .append("}");
        }
        return json.append("]}").toString();
    }

    private static String jsonString(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            switch (current) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (current < 0x20) {
                        out.append(String.format("\\u%04x", (int) current));
                    } else {
                        out.append(current);
                    }
                    break;
            }
        }
        return out.append("\"").toString();
    }

    private static final class UsageException extends Exception {
        UsageException(String message) {
            super(message);
        }
    }
}
