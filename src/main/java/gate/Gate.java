package gate;

import java.util.*;

/** Evaluates the licences in a CycloneDX SBOM against a policy. */
public final class Gate {
    public enum Verdict { ALLOWED, REVIEW, DENIED }
    public record Policy(Set<String> allow, Set<String> deny, Set<String> copyleft) {}
    public record Row(String component, String version, String license, Verdict verdict, String why) {}
    public record Report(List<Row> rows, int total) {
        public long count(Verdict v) { return rows.stream().filter(r -> r.verdict == v).count(); }
    }

    public static final Policy DEFAULT = new Policy(
        norm("MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,0BSD,Unlicense,CC0-1.0,Zlib,BlueOak-1.0.0,Python-2.0,PSF-2.0"),
        norm("AGPL-3.0-only,AGPL-3.0-or-later,SSPL-1.0,BUSL-1.1,Commons-Clause,CPAL-1.0"),
        norm("GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-only,GPL-3.0-or-later,LGPL-2.1-only,LGPL-2.1-or-later,LGPL-3.0-only,LGPL-3.0-or-later,MPL-2.0,EPL-1.0,EPL-2.0,CDDL-1.0,CDDL-1.1"));

    static Set<String> norm(String csv) {
        Set<String> s = new TreeSet<>();
        for (String x : csv.split(",")) if (!x.isBlank()) s.add(x.trim().toLowerCase(Locale.ROOT));
        return s;
    }

    public static Policy policy(String allow, String deny, String copyleft) {
        return new Policy(allow == null ? DEFAULT.allow() : norm(allow), deny == null ? DEFAULT.deny() : norm(deny), copyleft == null ? DEFAULT.copyleft() : norm(copyleft));
    }

    /** Licences of one component: SPDX ids, SPDX expressions (OR/AND) and free-text names. */
    static List<String> licenses(Map<String, Object> c) {
        List<String> out = new ArrayList<>();
        for (Object l : Json.arr(c.get("licenses"))) {
            Map<String, Object> m = Json.obj(l);
            Object expr = m.get("expression");
            if (expr instanceof String e) { out.add(e); continue; }
            Map<String, Object> lic = Json.obj(m.get("license"));
            Object id = lic.get("id"), name = lic.get("name");
            if (id instanceof String s) out.add(s); else if (name instanceof String n) out.add(n);
        }
        return out;
    }

    static Verdict judgeOne(String id, Policy p, StringBuilder why) {
        String k = id.toLowerCase(Locale.ROOT).trim();
        if (p.deny().contains(k)) { why.append(id).append(" is on the deny list"); return Verdict.DENIED; }
        if (p.allow().contains(k)) return Verdict.ALLOWED;
        if (p.copyleft().contains(k)) { why.append(id).append(" is copyleft: depends on how it is linked and distributed"); return Verdict.REVIEW; }
        why.append(id).append(" is not in the policy"); return Verdict.REVIEW;
    }

    /** SPDX expression: "A OR B" is satisfied by the best option, "A AND B" needs the worst. Parentheses are flattened conservatively. */
    static Verdict judgeExpression(String expr, Policy p, StringBuilder why) {
        String e = expr.replace("(", " ").replace(")", " ").trim();
        Verdict best = null;
        for (String orPart : e.split("(?i)\\s+OR\\s+")) {
            Verdict worst = Verdict.ALLOWED; StringBuilder w = new StringBuilder();
            for (String t : orPart.split("(?i)\\s+AND\\s+")) {
                String tok = t.trim().replaceAll("(?i)\\s+WITH\\s+.*$", "");
                if (tok.isEmpty()) continue;
                StringBuilder one = new StringBuilder();
                Verdict v = judgeOne(tok, p, one);
                if (v.ordinal() > worst.ordinal()) worst = v;
                if (one.length() > 0) { if (w.length() > 0) w.append("; "); w.append(one); }
            }
            if (best == null || worst.ordinal() < best.ordinal()) { best = worst; why.setLength(0); why.append(w); }
        }
        return best == null ? Verdict.REVIEW : best;
    }

    public static Report evaluate(String sbomJson, Policy p) {
        Object root = Json.parse(sbomJson);
        Map<String, Object> doc = Json.obj(root);
        if (!"CycloneDX".equals(doc.get("bomFormat"))) throw new Json.JsonException("not a CycloneDX SBOM (bomFormat must be CycloneDX)");
        List<Row> rows = new ArrayList<>();
        int total = 0;
        for (Object o : Json.arr(doc.get("components"))) {
            Map<String, Object> c = Json.obj(o);
            total++;
            String name = String.valueOf(c.getOrDefault("name", "(unnamed)")), ver = String.valueOf(c.getOrDefault("version", ""));
            List<String> ls = licenses(c);
            if (ls.isEmpty()) { rows.add(new Row(name, ver, "(none)", Verdict.REVIEW, "no licence declared: you have no right to use it until you know")); continue; }
            Verdict worst = Verdict.ALLOWED; StringBuilder why = new StringBuilder();
            for (String l : ls) {
                StringBuilder w = new StringBuilder();
                Verdict v = (l.matches("(?i).*\\s(AND|OR|WITH)\\s.*")) ? judgeExpression(l, p, w) : judgeOne(l, p, w);
                if (v.ordinal() > worst.ordinal()) { worst = v; why.setLength(0); }
                if (v == worst && w.length() > 0) { if (why.length() > 0) why.append("; "); why.append(w); }
            }
            if (worst != Verdict.ALLOWED) rows.add(new Row(name, ver, String.join(", ", ls), worst, why.toString()));
        }
        rows.sort(Comparator.comparing((Row r) -> r.verdict).reversed().thenComparing(Row::component));
        return new Report(rows, total);
    }

    public static String text(Report r) {
        StringBuilder b = new StringBuilder();
        b.append(r.total()).append(" components: ").append(r.count(Verdict.DENIED)).append(" denied, ").append(r.count(Verdict.REVIEW)).append(" need review, the rest allowed.\n");
        for (Row x : r.rows()) b.append(String.format("%-7s %s %s  [%s]%n        %s%n", x.verdict(), x.component(), x.version(), x.license(), x.why()));
        return b.toString();
    }

    static String esc(String s) { return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;"); }

    public static String html(Report r) {
        StringBuilder rows = new StringBuilder();
        for (Row x : r.rows()) rows.append("<tr><td class=\"").append(x.verdict().name().toLowerCase()).append("\">").append(x.verdict()).append("</td><td>").append(esc(x.component())).append(' ').append(esc(x.version())).append("</td><td>").append(esc(x.license())).append("</td><td>").append(esc(x.why())).append("</td></tr>");
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>sbom-license-gate</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}td.denied{color:#f85149;font-weight:700}td.review{color:#e3b341;font-weight:700}</style></head><body><h1>sbom-license-gate</h1><p class=\"sub\">Licence compliance gate for CycloneDX SBOMs. Java 17+, no dependencies. Synthetic SBOM, " + r.total() + " components.</p><p><b>" + r.count(Verdict.DENIED) + "</b> denied, <b>" + r.count(Verdict.REVIEW) + "</b> need review.</p><table><tr><th>Verdict</th><th>Component</th><th>Licence</th><th>Why</th></tr>" + rows + "</table><p class=\"sub\">A policy check, not legal advice. Copyleft is not automatically forbidden: it depends on how the code is linked and distributed.</p></body></html>\n";
    }
}
