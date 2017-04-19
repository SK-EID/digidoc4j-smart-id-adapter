package ee.sk.smartid.digidoc4j.exception;

import ee.sk.smartid.exception.SmartIdException;

public class DigestAlgorithmNotSupportedException extends SmartIdException {

  public DigestAlgorithmNotSupportedException(String message) {
    super(message);
  }
}
