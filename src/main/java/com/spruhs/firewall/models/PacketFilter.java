package com.spruhs.firewall.models;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static com.spruhs.firewall.models.Action.PERMIT;

public class PacketFilter extends Wall {

  private static final Logger LOG = LogManager.getLogger(PacketFilter.class);

  public PacketFilter(Action defaultAction) {
    super(defaultAction);
  }

  public boolean validateRequest(Request request) {
    Entry matchedEntry = findLastMatchingEntry(request);
    if (matchedEntry != null) {
      LOG.info("Request matches entry: {}", matchedEntry);
      return matchedEntry.action() == PERMIT;
    }
    return defaultAction == PERMIT;
  }

  private Entry findLastMatchingEntry(Request request) {
    return entries.stream()
      .filter(entry -> entry.matches(request))
      .reduce((first, second) -> second)
      .orElse(null);
  }
}
