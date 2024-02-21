package com.spruhs.firewall.models;

public record Entry(
  int id,
  String sourceIp,
  String sourcePort,
  String destinationIp,
  String destinationPort,
  Action action
) {

  public Entry {
    validateId(id);
    validatePort(sourcePort);
    validatePort(destinationPort);
    validateIp(sourceIp);
    validateIp(destinationIp);
  }

  private void validateId(int id) {
    if (id <= 0) {
      throw new IllegalArgumentException("Invalid id: " + id);
    }
  }

  private void validatePort(String port) {
    String regex = "^\\d+$|^\\*$";
    if (port == null || !port.matches(regex)) {
      throw new IllegalArgumentException("Invalid port: " + port);
    }
  }

  private void validateIp(String ip) {
    String regex = "^\\d+\\.\\d+\\.\\d+\\.\\d+$|^\\*$";
    if (ip == null || !ip.matches(regex)) {
      throw new IllegalArgumentException("Invalid ip: " + ip);
    }
  }

  public boolean matches(Request request) {
    return matchesSource(request) && matchesDestination(request);
  }

  private boolean matchesSource(Request request) {
    return (sourceIp.equals("*") || sourceIp.equals(request.sourceIp())) &&
           (sourcePort.equals("*") || sourcePort.equals(String.valueOf(request.sourcePort())));
  }

  private boolean matchesDestination(Request request) {
    return (destinationIp.equals("*") || destinationIp.equals(request.destIp())) &&
           (destinationPort.equals("*") || destinationPort.equals(String.valueOf(request.destPort())));
  }

}
