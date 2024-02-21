package com.spruhs.firewall.models;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IpTableTest {


  @Test
  void validateRequest_shouldPermit() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    IpTable ipTable = new IpTable(Action.REJECT);
    ipTable.add(new Entry(1, "192.0.0.1", "2", "192.0.0.3", "4", Action.PERMIT));
    ipTable.add(new Entry(2, "192.0.0.1", "2", "192.0.0.3", "4", Action.REJECT));
    assertTrue(ipTable.validateRequest(request));
  }

  @Test
  void validateRequest_shouldReject() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    IpTable ipTable = new IpTable(Action.REJECT);
    ipTable.add(new Entry(1, "192.0.0.1", "2", "192.0.0.3", "4", Action.REJECT));
    ipTable.add(new Entry(2, "192.0.0.1", "2", "192.0.0.3", "4", Action.PERMIT));
    assertFalse(ipTable.validateRequest(request));
  }

  @Test
  void validateRequest_shouldRejectDefault() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    IpTable ipTable = new IpTable(Action.REJECT);
    ipTable.add(new Entry(1, "192.0.0.1", "3", "192.0.0.3", "4", Action.PERMIT));
    ipTable.add(new Entry(2, "192.0.0.1", "3", "192.0.0.3", "4", Action.REJECT));
    assertFalse(ipTable.validateRequest(request));
  }

  @Test
  void validateRequest_shouldPermitDefault() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    IpTable ipTable = new IpTable(Action.PERMIT);
    ipTable.add(new Entry(1, "192.0.0.1", "3", "192.0.0.3", "4", Action.REJECT));
    ipTable.add(new Entry(2, "192.0.0.1", "3", "192.0.0.3", "4", Action.PERMIT));
    assertTrue(ipTable.validateRequest(request));
  }

}