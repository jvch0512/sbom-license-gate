package gate;

import java.util.*;

/** Minimal strict JSON parser: objects, arrays, strings, numbers, booleans, null. */
public final class Json {
    public static final class JsonException extends RuntimeException { public JsonException(String m) { super(m); } }
    private final String s; private int i;
    private Json(String s) { this.s = s; }

    public static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.i != text.length()) throw new JsonException("unexpected data at offset " + p.i);
        return v;
    }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private char peek() { if (i >= s.length()) throw new JsonException("unexpected end of input"); return s.charAt(i); }

    private Object value(int depth) {
        if (depth > 200) throw new JsonException("nesting too deep");
        char c = peek();
        if (c == '{') {
            i++; Map<String, Object> m = new LinkedHashMap<>(); ws();
            if (peek() == '}') { i++; return m; }
            while (true) {
                ws(); if (peek() != '"') throw new JsonException("expected a string key at offset " + i);
                String k = string(); ws();
                if (peek() != ':') throw new JsonException("expected ':' at offset " + i);
                i++; ws(); m.put(k, value(depth + 1)); ws();
                char d = peek(); i++;
                if (d == '}') return m;
                if (d != ',') throw new JsonException("expected ',' or '}' at offset " + (i - 1));
            }
        }
        if (c == '[') {
            i++; List<Object> l = new ArrayList<>(); ws();
            if (peek() == ']') { i++; return l; }
            while (true) {
                ws(); l.add(value(depth + 1)); ws();
                char d = peek(); i++;
                if (d == ']') return l;
                if (d != ',') throw new JsonException("expected ',' or ']' at offset " + (i - 1));
            }
        }
        if (c == '"') return string();
        if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
        if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
        if (s.startsWith("null", i)) { i += 4; return null; }
        int st = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        if (st == i) throw new JsonException("unexpected character '" + c + "' at offset " + i);
        try { return Double.parseDouble(s.substring(st, i)); } catch (NumberFormatException e) { throw new JsonException("bad number at offset " + st); }
    }

    private String string() {
        i++; StringBuilder b = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw new JsonException("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return b.toString();
            if (c == '\\') {
                char e = peek(); i++;
                switch (e) {
                    case '"', '\\', '/' -> b.append(e);
                    case 'b' -> b.append('\b'); case 'f' -> b.append('\f'); case 'n' -> b.append('\n'); case 'r' -> b.append('\r'); case 't' -> b.append('\t');
                    case 'u' -> { if (i + 4 > s.length()) throw new JsonException("bad unicode escape"); b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                    default -> throw new JsonException("bad escape at offset " + (i - 1));
                }
            } else b.append(c);
        }
    }

    @SuppressWarnings("unchecked") public static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : Map.of(); }
    @SuppressWarnings("unchecked") public static List<Object> arr(Object o) { return o instanceof List ? (List<Object>) o : List.of(); }
}
