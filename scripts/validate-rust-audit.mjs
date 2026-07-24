import { readFileSync } from "node:fs";

const expectedTuples = new Set([
  "RUSTSEC-2026-0194\u0000quick-xml\u00000.37.5",
  "RUSTSEC-2026-0195\u0000quick-xml\u00000.37.5",
]);

function validate(report) {
  const vulnerabilities = report?.vulnerabilities;
  if (
    vulnerabilities?.found !== true ||
    vulnerabilities?.count !== 2 ||
    !Array.isArray(vulnerabilities?.list) ||
    vulnerabilities.list.length !== 2
  ) {
    throw new Error("expected exactly two explicitly reviewed vulnerabilities");
  }

  const actualTuples = new Set(
    vulnerabilities.list.map((record) => {
      const advisory = record?.advisory?.id;
      const packageName = record?.package?.name;
      const packageVersion = record?.package?.version;
      if (
        typeof advisory !== "string" ||
        typeof packageName !== "string" ||
        typeof packageVersion !== "string"
      ) {
        throw new Error("malformed cargo-audit vulnerability record");
      }
      return `${advisory}\u0000${packageName}\u0000${packageVersion}`;
    }),
  );

  if (
    actualTuples.size !== expectedTuples.size ||
    [...actualTuples].some((tuple) => !expectedTuples.has(tuple))
  ) {
    throw new Error(
      "cargo-audit reported an unreviewed advisory, package, or version",
    );
  }
}

if (process.argv.length !== 3) {
  throw new Error("usage: validate-rust-audit.mjs <cargo-audit-json>");
}

const report = JSON.parse(readFileSync(process.argv[2], "utf8"));
validate(report);

// Exercise the fail-closed path on every run: a synthetic additional record
// must never be accepted by the same validator used for the real report.
const syntheticExtra = structuredClone(report);
syntheticExtra.vulnerabilities.count += 1;
syntheticExtra.vulnerabilities.list.push({
  advisory: { id: "RUSTSEC-SYNTHETIC-EXTRA" },
  package: { name: "synthetic", version: "1.0.0" },
});
let rejectedSyntheticExtra = false;
try {
  validate(syntheticExtra);
} catch {
  rejectedSyntheticExtra = true;
}
if (!rejectedSyntheticExtra) {
  throw new Error("validator accepted a synthetic additional vulnerability");
}

console.log(
  "Rust audit contains only the two reviewed, target-unreachable vulnerability tuples.",
);
