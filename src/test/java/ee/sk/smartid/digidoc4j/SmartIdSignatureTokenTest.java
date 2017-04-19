package ee.sk.smartid.digidoc4j;

import ee.sk.smartid.*;
import ee.sk.smartid.digidoc4j.exception.DigestAlgorithmNotSupportedException;
import ee.sk.smartid.rest.dao.NationalIdentity;
import org.apache.commons.codec.binary.Base64;
import org.digidoc4j.DigestAlgorithm;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;

@RunWith(MockitoJUnitRunner.class)
public class SmartIdSignatureTokenTest {

  @Mock
  private CertificateRequestBuilder certificateRequestBuilder;

  @Mock
  private SignatureRequestBuilder signatureRequestBuilder;

  @Spy
  private SmartIdClient client;

  private static final String DOCUMENT_NUMBER = "PNOEE-31111111111-K0DD-NQ";
  private static final NationalIdentity NATIONAL_IDENTITY = new NationalIdentity("EE", "31111111111");
  private static final String CERTIFICATE_LEVEL = "ADVANCED";
  private static final String NONCE = "nonce";
  private static final String DISPLAY_TEXT = "some text to display";
  private static final String DATA_TO_SIGN = "data to be signed";
  private static final String SIGNATURE_VALUE_IN_BASE64 = "c2lnbmF0dXJl";
  private static X509Certificate CERTIFICATE;

  @Before
  public void setUp() throws Exception {
    client.setRelyingPartyUUID("de305d54-75b4-431b-adb2-eb6b9e546014");
    client.setRelyingPartyName("BANK123");
    client.setHostUrl("http://localhost:8000");

    doReturn(certificateRequestBuilder).when(client).getCertificate();
    doReturn(signatureRequestBuilder).when(client).createSignature();

    doReturn(certificateRequestBuilder).when(certificateRequestBuilder).withDocumentNumber(DOCUMENT_NUMBER);
    doReturn(certificateRequestBuilder).when(certificateRequestBuilder).withNationalIdentity(NATIONAL_IDENTITY);
    doReturn(certificateRequestBuilder).when(certificateRequestBuilder).withNonce(NONCE);
    CERTIFICATE = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(SmartIdSignatureTokenTest.class.getClassLoader().getResourceAsStream("TEST_of_EID-SK_2016.pem.crt"));
    SmartIdCertificate smartIdCertificate = new SmartIdCertificate();
    smartIdCertificate.setCertificate(CERTIFICATE);
    smartIdCertificate.setDocumentNumber(DOCUMENT_NUMBER);
    doReturn(smartIdCertificate).when(certificateRequestBuilder).fetch();

    doReturn(signatureRequestBuilder).when(signatureRequestBuilder).withDocumentNumber(DOCUMENT_NUMBER);
    doReturn(signatureRequestBuilder).when(signatureRequestBuilder).withSignableData(any(SignableData.class));
    doReturn(signatureRequestBuilder).when(signatureRequestBuilder).withSignableHash(any(SignableHash.class));
    doReturn(signatureRequestBuilder).when(signatureRequestBuilder).withDisplayText(anyString());
    doReturn(signatureRequestBuilder).when(signatureRequestBuilder).withNonce(NONCE);
    SmartIdSignature signature = new SmartIdSignature();
    signature.setValueInBase64(SIGNATURE_VALUE_IN_BASE64);
    doReturn(signature).when(signatureRequestBuilder).sign();
  }

  @Test
  public void getCertificate_withDocumentNumber() {
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    X509Certificate certificate = signatureToken.getCertificate();

    InOrder inOrder = inOrder(certificateRequestBuilder);
    inOrder.verify(certificateRequestBuilder, times(1)).withDocumentNumber(DOCUMENT_NUMBER);
    inOrder.verify(certificateRequestBuilder, times(1)).fetch();
    assertEquals(CERTIFICATE.getSubjectDN(), certificate.getSubjectDN());
  }

  @Test
  public void getCertificate_withNationalIdentity() {
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, NATIONAL_IDENTITY);
    X509Certificate certificate = signatureToken.getCertificate();

    InOrder inOrder = inOrder(certificateRequestBuilder);
    inOrder.verify(certificateRequestBuilder, times(1)).withNationalIdentity(NATIONAL_IDENTITY);
    inOrder.verify(certificateRequestBuilder, times(1)).fetch();
    assertEquals(CERTIFICATE.getSubjectDN(), certificate.getSubjectDN());
  }

  @Test
  public void getCertificate_withCertificateLevelAndNonce() {
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    signatureToken.setCertificateLevel(CERTIFICATE_LEVEL);
    signatureToken.setNonce(NONCE);

    X509Certificate certificate = signatureToken.getCertificate();

    InOrder inOrder = inOrder(certificateRequestBuilder);
    inOrder.verify(certificateRequestBuilder, times(1)).withDocumentNumber(DOCUMENT_NUMBER);
    inOrder.verify(certificateRequestBuilder, times(1)).withCertificateLevel(CERTIFICATE_LEVEL);
    inOrder.verify(certificateRequestBuilder, times(1)).withNonce(NONCE);
    inOrder.verify(certificateRequestBuilder, times(1)).fetch();
    assertEquals(CERTIFICATE.getSubjectDN(), certificate.getSubjectDN());
  }

  @Test
  public void sign() {
    byte[] dataToSign = DATA_TO_SIGN.getBytes();
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    byte[] signature = signatureToken.sign(DigestAlgorithm.SHA256, dataToSign);

    ArgumentCaptor<SignableData> signableDataCaptor = ArgumentCaptor.forClass(SignableData.class);

    InOrder inOrder = inOrder(signatureRequestBuilder);
    inOrder.verify(signatureRequestBuilder, times(1)).withDocumentNumber(DOCUMENT_NUMBER);
    inOrder.verify(signatureRequestBuilder, times(1)).withSignableData(signableDataCaptor.capture());
    inOrder.verify(signatureRequestBuilder, times(1)).sign();

    assertEquals(HashType.SHA256, signableDataCaptor.getValue().getHashType());
    assertArrayEquals(DigestCalculator.calculateDigest(dataToSign, HashType.SHA256), signableDataCaptor.getValue().calculateHash());
    assertArrayEquals(Base64.decodeBase64(SIGNATURE_VALUE_IN_BASE64), signature);
  }

  @Test
  public void sign_withCertificateLevelAndDisplayTextAndNonce() {
    byte[] dataToSign = DATA_TO_SIGN.getBytes();
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    signatureToken.setCertificateLevel(CERTIFICATE_LEVEL);
    signatureToken.setDisplayText(DISPLAY_TEXT);
    signatureToken.setNonce(NONCE);
    byte[] signature = signatureToken.sign(DigestAlgorithm.SHA256, dataToSign);

    ArgumentCaptor<SignableData> signableDataCaptor = ArgumentCaptor.forClass(SignableData.class);

    InOrder inOrder = inOrder(signatureRequestBuilder);
    inOrder.verify(signatureRequestBuilder, times(1)).withDocumentNumber(DOCUMENT_NUMBER);
    inOrder.verify(signatureRequestBuilder, times(1)).withSignableData(signableDataCaptor.capture());
    inOrder.verify(signatureRequestBuilder, times(1)).withCertificateLevel(CERTIFICATE_LEVEL);
    inOrder.verify(signatureRequestBuilder, times(1)).withDisplayText(DISPLAY_TEXT);
    inOrder.verify(signatureRequestBuilder, times(1)).withNonce(NONCE);
    inOrder.verify(signatureRequestBuilder, times(1)).sign();

    assertEquals(HashType.SHA256, signableDataCaptor.getValue().getHashType());
    assertArrayEquals(DigestCalculator.calculateDigest(dataToSign, HashType.SHA256), signableDataCaptor.getValue().calculateHash());
    assertArrayEquals(Base64.decodeBase64(SIGNATURE_VALUE_IN_BASE64), signature);
  }

  @Test
  public void signDigest() {
    byte[] digestToSign = DigestCalculator.calculateDigest(DATA_TO_SIGN.getBytes(), HashType.SHA256);
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    byte[] signature = signatureToken.signDigest(DigestAlgorithm.SHA256, digestToSign);

    ArgumentCaptor<SignableHash> signableDataCaptor = ArgumentCaptor.forClass(SignableHash.class);

    InOrder inOrder = inOrder(signatureRequestBuilder);
    inOrder.verify(signatureRequestBuilder, times(1)).withDocumentNumber(DOCUMENT_NUMBER);
    inOrder.verify(signatureRequestBuilder, times(1)).withSignableHash(signableDataCaptor.capture());
    inOrder.verify(signatureRequestBuilder, times(1)).sign();

    assertEquals(HashType.SHA256, signableDataCaptor.getValue().getHashType());
    assertEquals(Base64.encodeBase64String(digestToSign), signableDataCaptor.getValue().getHashInBase64());
    assertArrayEquals(Base64.decodeBase64(SIGNATURE_VALUE_IN_BASE64), signature);
  }

  @Test
  public void signDigest_withCertificateLevelAndDisplayTextAndNonce() {
    byte[] digestToSign = DigestCalculator.calculateDigest(DATA_TO_SIGN.getBytes(), HashType.SHA256);
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    signatureToken.setCertificateLevel(CERTIFICATE_LEVEL);
    signatureToken.setDisplayText(DISPLAY_TEXT);
    signatureToken.setNonce(NONCE);
    byte[] signature = signatureToken.signDigest(DigestAlgorithm.SHA256, digestToSign);

    ArgumentCaptor<SignableHash> signableDataCaptor = ArgumentCaptor.forClass(SignableHash.class);

    InOrder inOrder = inOrder(signatureRequestBuilder);
    inOrder.verify(signatureRequestBuilder, times(1)).withDocumentNumber(DOCUMENT_NUMBER);
    inOrder.verify(signatureRequestBuilder, times(1)).withSignableHash(signableDataCaptor.capture());
    inOrder.verify(signatureRequestBuilder, times(1)).withCertificateLevel(CERTIFICATE_LEVEL);
    inOrder.verify(signatureRequestBuilder, times(1)).withDisplayText(DISPLAY_TEXT);
    inOrder.verify(signatureRequestBuilder, times(1)).withNonce(NONCE);
    inOrder.verify(signatureRequestBuilder, times(1)).sign();

    assertEquals(HashType.SHA256, signableDataCaptor.getValue().getHashType());
    assertEquals(Base64.encodeBase64String(digestToSign), signableDataCaptor.getValue().getHashInBase64());
    assertArrayEquals(Base64.decodeBase64(SIGNATURE_VALUE_IN_BASE64), signature);
  }

  @Test(expected = DigestAlgorithmNotSupportedException.class)
  public void sign_withUnsupportedDigestAlgorithm_shouldThrowException() {
    byte[] dataToSign = DATA_TO_SIGN.getBytes();
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    signatureToken.sign(DigestAlgorithm.SHA1, dataToSign);
  }

  @Test(expected = DigestAlgorithmNotSupportedException.class)
  public void signDigest_withUnsupportedDigestAlgorithm_shouldThrowException() {
    byte[] digestToSign = DigestCalculator.calculateDigest(DATA_TO_SIGN.getBytes(), HashType.SHA256);
    SmartIdSignatureToken signatureToken = new SmartIdSignatureToken(client, DOCUMENT_NUMBER);
    signatureToken.signDigest(DigestAlgorithm.SHA224, digestToSign);
  }
}
