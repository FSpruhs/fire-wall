package com.spruhs.firewall.models;

import java.util.LinkedList;
import java.util.List;

public class PacketFilter {

  private final List<Entry> entries = new LinkedList<>();
  private final Mode mode;

  public PacketFilter(Mode mode) {
    this.mode = mode;
  }

  public void add(Entry entry) {
    entries.add(entry);
  }

  public boolean validateRequest(Request request) {
    int id = 0;
    for (Entry entry : entries) {
      if (entry.matches(request)) {
        id = entry.id();
      }
    }
    if (id != 0) {
      System.out.println("Request matches entry: " + findById(id));
      return true;
    }
    return mode == Mode.PERMIT_ALL;
  }

  private String findById(int id) {
    return entries.stream().filter(entry -> entry.id() == id).findFirst().toString();
  }

  public void validateRequests(List<Request> requests) {
    for (Request request : requests) {
      System.out.println("--------------------");
      System.out.println("Request: " + request);
      System.out.println("Result: " + (validateRequest(request) ? "Permitted" : "Rejected"));
      System.out.println("--------------------");
      System.out.println("\n");
    }
  }


}
