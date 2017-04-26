package ee.sk.smartid.digidoc4j;

import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.VerificationCodeCalculator;
import ee.sk.smartid.rest.dao.NationalIdentity;
import org.digidoc4j.*;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertTrue;

@Ignore("Requires physical interaction with a Smart ID device")
public class SmartIdSignatureTokenIntegrationTest {

  // When using test configuration the signer's cert has to be uploaded to: https://demo.sk.ee/upload_cert/index.php to respond with "GOOD" status
  private Configuration configuration = new Configuration(Configuration.Mode.TEST);

  private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v1/";
  private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
  private static final String RELYING_PARTY_NAME = "DEMO";
  private static final String DOCUMENT_NUMBER = "PNOEE-31111111111-K0DD-NQ";
  private static final NationalIdentity NATIONAL_IDENTITY = new NationalIdentity("EE", "31111111111");
  private SmartIdClient client;

  @Before
  public void setUp() throws Exception {
    client = new SmartIdClient();
    client.setRelyingPartyUUID(RELYING_PARTY_UUID);
    client.setRelyingPartyName(RELYING_PARTY_NAME);
    client.setHostUrl(HOST_URL);

    // Trust issuing CA certificate of the signer
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    X509Certificate caCertificate = (X509Certificate) certFactory.generateCertificate(SmartIdSignatureTokenIntegrationTest.class.getClassLoader().getResourceAsStream("TEST_of_EID-SK_2016.pem.crt"));
    addTrustedCaCertificate(configuration, caCertificate);
  }

  @Test
  public void createBDOCContainer_withSignatureToken() {
    DataFile dataFile = new DataFile("sign me".getBytes(), "file_to_sign.txt", "text/plain");

    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(configuration).
        withDataFile(dataFile).
        build();

    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, NATIONAL_IDENTITY);

    Signature signature = SignatureBuilder.
        aSignature(container).
        withSignatureToken(signatureToken).
        invokeSigning();

    container.addSignature(signature);
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
  }

  @Test
  public void createBDOCContainer_withExternalStyleSigning() {
    DataFile dataFile = new DataFile("sign me too".getBytes(), "file_to_sign2.txt", "text/plain");

    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(configuration).
        withDataFile(dataFile).
        build();

    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;

    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signatureToken.getCertificate()).
        withSignatureDigestAlgorithm(digestAlgorithm).
        buildDataToSign();



    byte[] digestToSign = dataToSign.getDigestToSign();

    System.out.println(VerificationCodeCalculator.calculate(digestToSign));

    byte[] signatureValue = signatureToken.signDigest(digestAlgorithm, digestToSign);
    Signature signature = dataToSign.finalize(signatureValue);

    container.addSignature(signature);
    ValidationResult result = container.validate();
    assertTrue(result.isValid());
  }

  private void addTrustedCaCertificate(Configuration configuration, X509Certificate certificate) {
    TSLCertificateSource certificateSource = configuration.getTSL();
    certificateSource.addTSLCertificate(certificate);
  }
}
