package com.spruhs.firewall.models;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class IpTable {

  private static final Logger LOG = LogManager.getLogger(IpTable.class);

  private final List<Entry> entries = new LinkedList<>();
  private final Mode mode;

  public IpTable(Mode mode) {
    this.mode = mode;
  }

  public void add(Entry entry) {
    entries.add(entry);
  }

  public boolean validateRequest(Request request) {
    Entry matchedEntry = findFirstMatchingEntry(request);
    if (matchedEntry != null) {
      LOG.info("Request matches entry: {}", matchedEntry);
      return matchedEntry.action() == Action.PERMIT;
    }
    return mode == Mode.PERMIT_ALL;
  }

  private Entry findFirstMatchingEntry(Request request) {
    return entries.stream().filter(entry -> entry.matches(request)).findFirst().orElse(null);
  }

  public void validateRequests(List<Request> requests) {
    LOG.info("--------IP Table------------");
    for (Request request : requests) {
      LOG.info("Request: {}", request);
      LOG.info("Result: {}", (validateRequest(request) ? "Permitted" : "Rejected"));
      LOG.info("--------------------");
    }
  }
}
