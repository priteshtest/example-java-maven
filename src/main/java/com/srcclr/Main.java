package com.srcclr;

import org.apache.commons.fileupload.MultipartStream;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.elasticsearch.percolator.PercolatorService;
import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class Main {

  public static void main(String[] args) {
    String candidate = args[0];
    String hashed = BCrypt.hashpw(candidate, BCrypt.gensalt(12));

    BCrypt.checkpw(candidate, hashed);

    filterXMLSignature();

    PercolatorService s = new PercolatorService(null, null, null, null, null, null, null, null, null, null);
    s.close();
  }

  private static void filterXMLSignature() {
    byte[] bytes = new byte[256];

    try {
      new MultipartStream(new ByteArrayInputStream(bytes), bytes);
    } catch (IOException ignored) {
    }

    new XMLSignatureInput(bytes).addNodeFilter(null);
  }
}
