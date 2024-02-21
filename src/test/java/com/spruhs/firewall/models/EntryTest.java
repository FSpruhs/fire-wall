package com.spruhs.firewall.models;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class EntryTest {

  @ParameterizedTest
  @MethodSource("data")
  void matches(Entry entry, Request request, boolean expected) {
    assertEquals(expected, entry.matches(request));
  }

  static Stream<Arguments> data() {
    return Stream.of(
      Arguments.of(
        new Entry(1, "*", "*", "*", "*", Action.REJECT),
        new Request("192.0.0.1", 0, "192.0.0.1", 0),
        true
      ),
      Arguments.of(
        new Entry(1, "192.0.0.1", "2", "192.0.0.3", "4", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        true
      ),
      Arguments.of(
        new Entry(1, "*", "2", "192.0.0.3", "4", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        true
      ),
      Arguments.of(
        new Entry(1, "192.0.0.1", "*", "192.0.0.3", "4", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        true
      ),
      Arguments.of(
        new Entry(1, "192.0.0.1", "2", "*", "4", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        true
      ),
      Arguments.of(
        new Entry(1, "192.0.0.1", "2", "192.0.0.3", "*", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        true
      ),
      Arguments.of(
        new Entry(1, "192.0.0.2", "2", "192.0.0.3", "4", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        false
      ),
      Arguments.of(
        new Entry(1, "192.0.0.1", "3", "192.0.0.3", "4", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        false
      ),
      Arguments.of(
        new Entry(1, "192.0.0.1", "2", "192.0.0.4", "4", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        false
      ),
      Arguments.of(
        new Entry(1, "192.0.0.1", "2", "192.0.0.3", "5", Action.REJECT),
        new Request("192.0.0.1", 2, "192.0.0.3", 4),
        false
      )
    );
  }
}