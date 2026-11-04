package com.zerotrust.service.scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Case-insensitive, multi-valued view of HTTP response headers.
 */
public final class ResponseHeaders {

    public record Header(String name, String value) {
    }

    private final List<Header> headers;

    public ResponseHeaders(List<Header> headers) {
        this.headers = List.copyOf(headers);
    }

    public static ResponseHeaders of(Map<String, String> values) {
        List<Header> list = new ArrayList<>();
        values.forEach((name, value) -> list.add(new Header(name, value)));
        return new ResponseHeaders(list);
    }

    /** First value of the header, or null when absent. */
    public String first(String name) {
        for (Header h : headers) {
            if (h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return null;
    }

    public List<String> all(String name) {
        List<String> values = new ArrayList<>();
        for (Header h : headers) {
            if (h.name().equalsIgnoreCase(name)) {
                values.add(h.value());
            }
        }
        return values;
    }

    public boolean contains(String name) {
        return first(name) != null;
    }

    public List<Header> asList() {
        return headers;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        for (Header h : headers) {
            sb.append(h.name().toLowerCase(Locale.ROOT)).append(": ").append(h.value()).append('\n');
        }
        return sb.toString();
    }
}
