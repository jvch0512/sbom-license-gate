package gate;

import java.nio.file.*;
import java.util.*;

public final class Main {
    static final String USAGE = "sbom-license-gate <sbom.json> [--allow ids] [--deny ids] [--copyleft ids] [--html] [--fail-on denied|review]\n\nIds are comma-separated SPDX identifiers that replace the built-in lists.\nExit codes: 0 ok, 1 findings at or above --fail-on, 2 bad input.";

    public static void main(String[] a) { System.exit(run(a)); }

    static int run(String[] a) {
        if (a.length == 0 || a[0].startsWith("--")) { System.err.println(USAGE); return 2; }
        String allow = null, deny = null, copyleft = null, failOn = null; boolean html = false;
        for (int i = 1; i < a.length; i++) {
            switch (a[i]) {
                case "--html" -> html = true;
                case "--allow", "--deny", "--copyleft", "--fail-on" -> {
                    if (i + 1 >= a.length) { System.err.println("error: " + a[i] + " needs a value"); return 2; }
                    String v = a[++i];
                    switch (a[i - 1]) { case "--allow" -> allow = v; case "--deny" -> deny = v; case "--copyleft" -> copyleft = v; default -> failOn = v; }
                }
                default -> { System.err.println("error: unknown option " + a[i] + "\n" + USAGE); return 2; }
            }
        }
        if (failOn != null && !failOn.equals("denied") && !failOn.equals("review")) { System.err.println("error: --fail-on must be denied or review"); return 2; }
        try {
            Gate.Report r = Gate.evaluate(Files.readString(Path.of(a[0])), Gate.policy(allow, deny, copyleft));
            System.out.print(html ? Gate.html(r) : Gate.text(r));
            if ("denied".equals(failOn) && r.count(Gate.Verdict.DENIED) > 0) return 1;
            if ("review".equals(failOn) && (r.count(Gate.Verdict.DENIED) + r.count(Gate.Verdict.REVIEW)) > 0) return 1;
            return 0;
        } catch (Json.JsonException e) { System.err.println("error: " + e.getMessage()); return 2; }
        catch (java.io.IOException e) { System.err.println("error: " + e.getMessage()); return 2; }
    }
}
