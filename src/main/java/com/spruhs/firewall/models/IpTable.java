package com.spruhs.firewall.models;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static com.spruhs.firewall.models.Action.PERMIT;


public class IpTable extends Wall {

  private static final Logger LOG = LogManager.getLogger(IpTable.class);

  public IpTable(Action defaultAction) {
    super(defaultAction);
  }

  public boolean validateRequest(Request request) {
    Entry matchedEntry = findFirstMatchingEntry(request);
    if (matchedEntry != null) {
      LOG.info("Request matches entry: {}", matchedEntry);
      return matchedEntry.action() == PERMIT;
    }
    return defaultAction == PERMIT;
  }

  private Entry findFirstMatchingEntry(Request request) {
    return entries.stream().filter(entry -> entry.matches(request)).findFirst().orElse(null);
  }

}
