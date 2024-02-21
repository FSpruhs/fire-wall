package com.spruhs.firewall.models;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public abstract class Wall {

  private static final Logger LOG = LogManager.getLogger(Wall.class);

  protected final List<Entry> entries = new LinkedList<>();
  protected final Action defaultAction;

  protected Wall(Action defaultAction) {
    this.defaultAction = defaultAction;
  }

  public void add(Entry entry) {
    entries.add(entry);
  }

  public abstract boolean validateRequest(Request request);

  public void validateRequests(List<Request> requests) {
    LOG.info("--------Packet Filter------------");
    for (Request request : requests) {
      LOG.info("Request: {}", request);
      LOG.info("Result: {}", (validateRequest(request) ? "Permitted" : "Rejected"));
      LOG.info("--------------------");
    }
  }

}
