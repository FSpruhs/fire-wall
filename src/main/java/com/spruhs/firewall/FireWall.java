package com.spruhs.firewall;

import com.spruhs.firewall.models.Entry;
import com.spruhs.firewall.models.Mode;
import com.spruhs.firewall.models.PacketFilter;
import com.spruhs.firewall.models.Request;
import com.spruhs.firewall.models.IpTable;

import java.util.List;

import static com.spruhs.firewall.models.Action.PERMIT;
import static com.spruhs.firewall.models.Action.REJECT;

public class FireWall {

  public static void main(String[] args) {
    testIpTables();
    testPacketFilter();
  }

  private static void testPacketFilter() {
    PacketFilter packetFilter = new PacketFilter(Mode.REJECT_ALL);
    packetFilter.add(new Entry(1, "141.71.1.3", "29", "*", "*", PERMIT));
    packetFilter.add(new Entry(2, "*", "*", "10.71.132.2", "23", REJECT));
    packetFilter.add(new Entry(3, "*", "*", "*", "23", PERMIT));
    packetFilter.add(new Entry(4, "141.71.1.2", "28", "10.71.132.3", "27", REJECT));
    packetFilter.add(new Entry(5, "141.71.1.2", "28", "*", "*", PERMIT));
    packetFilter.add(new Entry(6, "141.71.1.1", "*", "10.71.132.4", "110", REJECT));

    List<Request> requests = List.of(
      new Request("141.71.1.2", 28, "10.71.132.3", 27),
      new Request("142.71.1.2", 28, "11.71.132.3", 27)
    );

    packetFilter.validateRequests(requests);

  }

  private static void testIpTables() {
    IpTable ipTable = new IpTable(Mode.REJECT_ALL);
    ipTable.add(new Entry(1, "141.71.1.3", "29", "*", "*", PERMIT));
    ipTable.add(new Entry(2, "*", "*", "10.71.132.2", "23", REJECT));
    ipTable.add(new Entry(3, "*", "*", "*", "23", PERMIT));
    ipTable.add(new Entry(4, "141.71.1.2", "28", "10.71.132.3", "27", REJECT));
    ipTable.add(new Entry(5, "141.71.1.2", "28", "*", "*", PERMIT));
    ipTable.add(new Entry(6, "141.71.1.1", "*", "10.71.132.4", "110", REJECT));
    ipTable.add(new Entry(7, "*", "*", "*", "*", PERMIT));

    List<Request> requests = List.of(
      new Request("141.71.1.2", 28, "10.71.132.3", 27),
      new Request("142.71.1.2", 28, "11.71.132.3", 27)
    );

    ipTable.validateRequests(requests);
  }

}
