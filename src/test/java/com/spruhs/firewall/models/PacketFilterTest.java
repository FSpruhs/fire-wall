package com.spruhs.firewall.models;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PacketFilterTest {

  @Test
  void validateRequest_shouldPermit() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    PacketFilter packetFilter = new PacketFilter(Action.REJECT);
    packetFilter.add(new Entry(1, "192.0.0.1", "2", "192.0.0.3", "4", Action.PERMIT));
    packetFilter.add(new Entry(2, "192.0.0.1", "2", "192.0.0.3", "4", Action.REJECT));
    assertFalse(packetFilter.validateRequest(request));
  }

  @Test
  void validateRequest_shouldReject() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    PacketFilter packetFilter = new PacketFilter(Action.REJECT);
    packetFilter.add(new Entry(1, "192.0.0.1", "2", "192.0.0.3", "4", Action.REJECT));
    packetFilter.add(new Entry(2, "192.0.0.1", "2", "192.0.0.3", "4", Action.PERMIT));
    assertTrue(packetFilter.validateRequest(request));
  }

  @Test
  void validateRequest_shouldRejectDefault() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    PacketFilter packetFilter = new PacketFilter(Action.REJECT);
    packetFilter.add(new Entry(1, "192.0.0.1", "3", "192.0.0.3", "4", Action.PERMIT));
    packetFilter.add(new Entry(2, "192.0.0.1", "3", "192.0.0.3", "4", Action.REJECT));
    assertFalse(packetFilter.validateRequest(request));
  }

  @Test
  void validateRequest_shouldPermitDefault() {
    Request request = new Request("192.0.0.1", 2, "192.0.0.3", 4);

    PacketFilter packetFilter = new PacketFilter(Action.PERMIT);
    packetFilter.add(new Entry(1, "192.0.0.1", "3", "192.0.0.3", "4", Action.REJECT));
    packetFilter.add(new Entry(2, "192.0.0.1", "3", "192.0.0.3", "4", Action.PERMIT));
    assertTrue(packetFilter.validateRequest(request));
  }

}