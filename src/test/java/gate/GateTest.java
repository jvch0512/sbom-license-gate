package gate;

import java.nio.file.*;
import java.util.*;

/** Dependency-free test runner: `java -cp out gate.GateTest` exits non-zero on failure. */
public final class GateTest {
    static int n, fail;
    static void check(String name, boolean ok) { n++; if (!ok) { fail++; System.out.println("FAIL: " + name); } }

    static String bom(String components) { return "{\"bomFormat\":\"CycloneDX\",\"components\":[" + components + "]}"; }
    static String comp(String lic) { return "{\"name\":\"x\",\"version\":\"1\",\"licenses\":[" + lic + "]}"; }
    static Gate.Verdict one(String lic) { var r = Gate.evaluate(bom(comp(lic)), Gate.DEFAULT); return r.rows().isEmpty() ? Gate.Verdict.ALLOWED : r.rows().get(0).verdict(); }

    public static void main(String[] args) throws Exception {
        check("permissive is allowed", one("{\"license\":{\"id\":\"MIT\"}}") == Gate.Verdict.ALLOWED);
        check("agpl is denied", one("{\"license\":{\"id\":\"AGPL-3.0-only\"}}") == Gate.Verdict.DENIED);
        check("gpl needs review", one("{\"license\":{\"id\":\"GPL-3.0-only\"}}") == Gate.Verdict.REVIEW);
        check("unknown licence needs review", one("{\"license\":{\"name\":\"Acme Internal\"}}") == Gate.Verdict.REVIEW);
        check("case-insensitive ids", one("{\"license\":{\"id\":\"apache-2.0\"}}") == Gate.Verdict.ALLOWED);
        check("OR picks the best option", one("{\"expression\":\"MIT OR GPL-3.0-only\"}") == Gate.Verdict.ALLOWED);
        check("AND needs the worst", one("{\"expression\":\"Apache-2.0 AND GPL-3.0-only\"}") == Gate.Verdict.REVIEW);
        check("WITH exception is read as its base licence", one("{\"expression\":\"GPL-2.0-only WITH Classpath-exception-2.0\"}") == Gate.Verdict.REVIEW);
        check("parentheses are handled", one("{\"expression\":\"(MIT OR Apache-2.0) AND BSD-3-Clause\"}") == Gate.Verdict.ALLOWED);
        check("worst of several licence entries", one("{\"license\":{\"id\":\"MIT\"}},{\"license\":{\"id\":\"SSPL-1.0\"}}") == Gate.Verdict.DENIED);
        var none = Gate.evaluate(bom("{\"name\":\"nolic\"}"), Gate.DEFAULT);
        check("missing licence needs review", none.rows().size() == 1 && none.rows().get(0).verdict() == Gate.Verdict.REVIEW);
        var custom = Gate.evaluate(bom(comp("{\"license\":{\"id\":\"MIT\"}}")), Gate.policy("Apache-2.0", null, null));
        check("custom allow list replaces the default", custom.rows().size() == 1);
        for (String bad : new String[] {"{", "[]", "{\"bomFormat\":\"SPDX\"}", "nope"}) {
            try { Gate.evaluate(bad, Gate.DEFAULT); check("bad input rejected: " + bad, false); } catch (Json.JsonException e) { check("bad input rejected: " + bad, true); }
        }
        check("json escapes", Json.parse("\"a\\n\\u0041\"").equals("a\nA"));
        var r = Gate.evaluate(Files.readString(Path.of("examples/sbom.json")), Gate.DEFAULT);
        check("sample: 16 components", r.total() == 16);
        check("sample: two denied", r.count(Gate.Verdict.DENIED) == 2);
        check("sample: dual licence is fine", r.rows().stream().noneMatch(x -> x.component().equals("dual-licensed-lib")));
        check("sample: denied first", r.rows().get(0).verdict() == Gate.Verdict.DENIED);
        var evil = new Gate.Report(List.of(new Gate.Row("<img src=x>", "1", "<b>", Gate.Verdict.REVIEW, "<script>")), 1);
        check("html escapes", !Gate.html(evil).contains("<img src=x>") && !Gate.html(evil).contains("<script>"));
        check("cli: missing file is exit 2", Main.run(new String[] {"nope.json"}) == 2);
        System.out.println(fail == 0 ? "all " + n + " passed" : fail + " of " + n + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
