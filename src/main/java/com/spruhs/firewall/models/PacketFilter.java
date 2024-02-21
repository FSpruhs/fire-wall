package com.spruhs.firewall.models;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketFilter extends Wall {

  private static final Logger LOG = LogManager.getLogger(PacketFilter.class);

  public PacketFilter(Mode mode) {
    super(mode);
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
}
