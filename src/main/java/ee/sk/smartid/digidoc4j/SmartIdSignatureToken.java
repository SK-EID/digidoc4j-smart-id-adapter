package ee.sk.smartid.digidoc4j;

import ee.sk.smartid.*;
import ee.sk.smartid.digidoc4j.exception.DigestAlgorithmNotSupportedException;
import ee.sk.smartid.exception.*;
import ee.sk.smartid.rest.dao.NationalIdentity;

import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;

import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Signature token implementation for Smart-ID
 * <p>
 * Can be used with DigiDoc4J to create digitally signed containers.
 * <p>
 * Example using Smart-ID signature token with DigiDoc4J to create BDOC container:
 * <pre class="code"><code class="java">
 *   // Smart-ID client setup. Note that these values are demo environment specific.
 *   SmartIdClient client = new SmartIdClient();
 *   client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
 *   client.setRelyingPartyName("DEMO");
 *   client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v1/");
 *
 *   // Smart-ID signature token setup
 *   NationalIdentity identity = new NationalIdentity("EE", "31111111111");
 *   SmartIdSignatureToken smartIdSignatureToken = new SmartIdSignatureToken(client, identity);
 *
 *   // Create a container with a text file to be signed
 *   Container container = ContainerBuilder.
 *       aContainer().
 *       withDataFile("testFiles/legal_contract_1.txt", "text/plain").
 *       build();
 *
 *   // Get the certificate
 *   X509Certificate signingCert = smartIdSignatureToken.getCertificate()
 *
 *   // Get the data to be signed by the user
 *   DataToSign dataToSign = SignatureBuilder.
 *   aSignature(container).
 *   withSigningCertificate(signingCert).
 *   withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
 *   buildDataToSign();
 *
 *   // Data to sign contains the digest that should be signed
 *   byte[] digestToSign = dataToSign.getDigestToSign();
 *
 *   // Calculate the verification code to display
 *   VerificationCodeCalculator.calculate(digestToSign);
 *
 *   // Sign the digest
 *   byte[] signatureValue = smartIdSignatureToken.signDigest(DigestAlgorithm.SHA256, digestToSign);
 *
 *   // Finalize the signature with OCSP response and timestamp (or timemark)
 *   Signature signature = dataToSign.finalize(signatureValue);
 *
 *   // Add signature to the container
 *   container.addSignature(signature);
 * </code></pre>
 */
public class SmartIdSignatureToken implements SignatureToken {

  private NationalIdentity identity;
  private String documentNumber;
  private SmartIdClient client;
  private String certificateLevel;
  private String nonce;
  private String displayText;

  /**
   * Constructs a new {@code SmartIdSignatureToken}
   *
   * @param client the configured client to communicate with the server
   * @param identity national identity of the person to sign
   */
  public SmartIdSignatureToken(SmartIdClient client, NationalIdentity identity) {
    this.client = client;
    this.identity = identity;
  }

  /**
   * Constructs a new {@code SmartIdSignatureToken}
   *
   * @param client the configured client to communicate with the server
   * @param documentNumber document number of the certificate/device used for signing
   */
  public SmartIdSignatureToken(SmartIdClient client, String documentNumber) {
    this.documentNumber = documentNumber;
    this.client = client;
  }

  /**
   * Sets the certificate level for certificate choice and signature requests
   *
   * @param certificateLevel level of the requested certificate
   *
   * @see ee.sk.smartid.CertificateRequestBuilder#withCertificateLevel(String)
   * @see ee.sk.smartid.SignatureRequestBuilder#withCertificateLevel(String)
   */
  public void setCertificateLevel(String certificateLevel) {
    this.certificateLevel = certificateLevel;
  }

  /**
   * Sets the nonce for certificate choice and signature requests
   *
   * @param nonce nonce of the requests
   *
   * @see ee.sk.smartid.CertificateRequestBuilder#withNonce(String)
   * @see ee.sk.smartid.SignatureRequestBuilder#withNonce(String)
   */
  public void setNonce(String nonce) {
    this.nonce = nonce;
  }

  /**
   * Sets the signature request's display text
   *
   * @param displayText text to display
   *
   * @see ee.sk.smartid.SignatureRequestBuilder#withDisplayText(String)
   */
  public void setDisplayText(String displayText) {
    this.displayText = displayText;
  }

  /**
   * Creates the certificate request and gets the signer's certificate
   *
   * @throws InvalidParametersException when mandatory request parameters are missing
   * @throws CertificateNotFoundException when the certificate was not found
   * @throws RequestForbiddenException when Relying Party has no permission to issue the request.
   *                                   This may happen when Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
   * @throws UserRefusedException when the user has refused the session
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   *                                   User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
   * @throws TechnicalErrorException when session status response's result is missing or it has some unknown value
   * @throws ClientNotSupportedException when the client-side implementation of this API is old and not supported any more
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @return signer's certificate
   */
  @Override
  public X509Certificate getCertificate() {
    CertificateRequestBuilder builder = client.getCertificate();

    if (identity != null) {
      builder.withNationalIdentity(identity);
    } else {
      builder.withDocumentNumber(documentNumber);
    }
    if (!StringUtils.isEmpty(certificateLevel)) {
      builder.withCertificateLevel(certificateLevel);
    }
    if (!StringUtils.isEmpty(nonce)) {
      builder.withNonce(nonce);
    }

    SmartIdCertificate smartIdCertificate = builder.fetch();
    documentNumber = smartIdCertificate.getDocumentNumber();
    return smartIdCertificate.getCertificate();
  }

  /**
   * Creates the signature request and gets the signature
   *
   * @throws InvalidParametersException when mandatory request parameters are missing
   * @throws UserAccountNotFoundException when the user account was not found
   * @throws RequestForbiddenException when Relying Party has no permission to issue the request.
   *                                   This may happen when Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
   * @throws UserRefusedException when the user has refused the session
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   *                                   User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
   * @throws TechnicalErrorException when session status response's result is missing or it has some unknown value
   * @throws ClientNotSupportedException when the client-side implementation of this API is old and not supported any more
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @param digestAlgorithm target digest algorithm of {@code dataToSign} to what it will be hashed before it is signed
   * @param dataToSign data to be signed in raw (not in hashed) format
   */
  @Override
  public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
    SignableData signableData = new SignableData(dataToSign);
    signableData.setHashType(getHashType(digestAlgorithm));

    SignatureRequestBuilder builder = client
        .createSignature()
        .withDocumentNumber(documentNumber)
        .withSignableData(signableData);

    if (!StringUtils.isEmpty(certificateLevel)) {
      builder.withCertificateLevel(certificateLevel);
    }
    if (!StringUtils.isEmpty(displayText)) {
      builder.withDisplayText(displayText);
    }
    if (!StringUtils.isEmpty(nonce)) {
      builder.withNonce(nonce);
    }

    SmartIdSignature signature = builder.sign();
    return signature.getValue();
  }

  /**
   * Creates the signature request and gets the signature
   *
   * @throws InvalidParametersException when mandatory request parameters are missing
   * @throws UserAccountNotFoundException when the user account was not found
   * @throws RequestForbiddenException when Relying Party has no permission to issue the request.
   *                                   This may happen when Relying Party has no permission to invoke operations on accounts with ADVANCED certificates.
   * @throws UserRefusedException when the user has refused the session
   * @throws SessionTimeoutException when there was a timeout, i.e. end user did not confirm or refuse the operation within given timeframe
   * @throws DocumentUnusableException when for some reason, this relying party request cannot be completed.
   *                                   User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
   * @throws TechnicalErrorException when session status response's result is missing or it has some unknown value
   * @throws ClientNotSupportedException when the client-side implementation of this API is old and not supported any more
   * @throws ServerMaintenanceException when the server is under maintenance
   *
   * @param digestAlgorithm digest algorithm of {@code hashToSign}
   * @param hashToSign hashed data to be signed
   */
  public byte[] signDigest(DigestAlgorithm digestAlgorithm, byte[] hashToSign) {
    SignableHash signableHash = new SignableHash();
    signableHash.setHash(hashToSign);
    signableHash.setHashType(getHashType(digestAlgorithm));

    SignatureRequestBuilder builder = client
        .createSignature()
        .withDocumentNumber(documentNumber)
        .withSignableHash(signableHash);

    if (!StringUtils.isEmpty(certificateLevel)) {
      builder.withCertificateLevel(certificateLevel);
    }
    if (!StringUtils.isEmpty(displayText)) {
      builder.withDisplayText(displayText);
    }
    if (!StringUtils.isEmpty(nonce)) {
      builder.withNonce(nonce);
    }

    SmartIdSignature signature = builder.sign();
    return signature.getValue();
  }

  private HashType getHashType(DigestAlgorithm digestAlgorithm) {
    for (HashType hashType : HashType.values()) {
      if (hashType.name().equals(digestAlgorithm.name())) {
        return hashType;
      }
    }
    throw new DigestAlgorithmNotSupportedException(digestAlgorithm.name() + " digest algorithm is not supported by Smart-ID. Supported algorigthms: " + Arrays.asList(HashType.values()));
  }
}