package com.spruhs.firewall.models;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class PacketFilter {

  private static final Logger LOG = LogManager.getLogger(PacketFilter.class);

  private final List<Entry> entries = new LinkedList<>();
  private final Mode mode;

  public PacketFilter(Mode mode) {
    this.mode = mode;
  }

  public void add(Entry entry) {
    entries.add(entry);
  }

  public boolean validateRequest(Request request) {
    Entry matchedEntry = findLastMatchingEntry(request);
    if (matchedEntry != null) {
      LOG.info("Request matches entry: {}", matchedEntry);
      return matchedEntry.action() == Action.PERMIT;
    }
    return mode == Mode.PERMIT_ALL;
  }

  private Entry findLastMatchingEntry(Request request) {
    return entries.stream()
      .filter(entry -> entry.matches(request))
      .reduce((first, second) -> second)
      .orElse(null);
  }

  public void validateRequests(List<Request> requests) {
    LOG.info("--------Packet Filter------------");
    for (Request request : requests) {
      LOG.info("Request: {}", request);
      LOG.info("Result: {}", (validateRequest(request) ? "Permitted" : "Rejected"));
      LOG.info("--------------------");
    }
  }
}
