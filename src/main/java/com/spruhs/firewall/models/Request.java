package com.spruhs.firewall.models;

public record Request(
    String sourceIp,
    int sourcePort,
    String destIp,
    int destPort
) {

  public Request {
    validateIp(sourceIp);
    validateIp(destIp);
  }

  private void validateIp(String ip) {
    String regex = "^\\d+\\.\\d+\\.\\d+\\.\\d+$";
    if (ip == null || !ip.matches(regex)) {
      throw new IllegalArgumentException("Invalid input: " + ip);
    }
  }

}
