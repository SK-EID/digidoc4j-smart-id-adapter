package ee.sk.smartid.digidoc4j;

import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.SignatureToken;

import java.security.cert.X509Certificate;

/**
 * TODO: Implement {@link ee.sk.smartid.digidoc4j.SmartIdSignatureToken}
 */
public class SmartIdSignatureToken implements SignatureToken {
  public X509Certificate getCertificate() {
    return null;
  }

  public byte[] sign(DigestAlgorithm digestAlgorithm, byte[] dataToSign) {
    return new byte[0];
  }
}