package com.spruhs.firewall.models;


import java.util.LinkedList;
import java.util.List;

public class Table {

  private final List<Entry> entries = new LinkedList<>();
  private final Mode mode;

  public Table(Mode mode) {
    this.mode = mode;
  }

  public void add(Entry entry) {
    entries.add(entry);
  }

  public boolean validateRequest(Request request) {
    for (Entry entry : entries) {
      if (entry.matches(request)) {
        System.out.println("Request matches entry: " + entry);
        return entry.action() == Action.PERMIT;
      }
    }
    return mode == Mode.PERMIT_ALL;
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
