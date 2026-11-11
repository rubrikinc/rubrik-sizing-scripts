// Builds scripts from each run guide with the options that matter, and checks them.
// Usage: node check_guides.js   (needs node and bash). Prints "ok <name>" / "FAIL <name>"; exit 1 on any FAIL.
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");
const { spawnSync } = require("child_process");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "run-guides-"));
const results = [];
const check = (name, ok) => results.push([name, !!ok]);

function load(name) {
  const html = fs.readFileSync(path.join(__dirname, `${name}-run-guide.html`), "utf8");
  const block = html.split("<script>").map((p) => p.split("</script>")[0]).find((p) => p.includes("function buildScript"));
  const context = { module: { exports: {} }, console };
  vm.runInNewContext(block, context);
  return { html, g: context.module.exports };
}

function validBash(script, label) {
  const file = path.join(tmp, `${label}.sh`);
  fs.writeFileSync(file, script);
  return spawnSync("bash", ["-n", file]).status === 0;
}

const commandLine = (script) => script.split("\n").filter((l) => l.startsWith("python main.py")).join("\n");
const base = { outDir: "./output", cloud: "auto", noCost: true, noDevops: true };
const tools = {
  aws: { ...base, mode: "single", services: [] },
  azure: { ...base, mode: "current", subs: "" },
  gcp: { ...base, mode: "current", collectors: ["asset", "compute", "storage", "database", "bigquery", "backup"] },
};

for (const [name, config] of Object.entries(tools)) {
  const { html, g } = load(name);
  check(`${name}: the verbose box is not ticked by default`, !/id="verbose"[^>]*checked/.test(html));
  for (const verbose of [false, true]) {
    const script = g.buildScript({ ...config, verbose });
    check(`${name}: verbose=${verbose} gives valid bash`, validBash(script, `${name}-${verbose}`));
    check(`${name}: --verbose appears only when ticked (verbose=${verbose})`, commandLine(script).includes("--verbose") === verbose);
  }
}

const aws = load("aws");
check("aws: the preflight-only box is not ticked by default", !/id="preflightOnly"[^>]*checked/.test(aws.html));
for (const mode of ["single", "org"]) {
  for (const preflightOnly of [false, true]) {
    const config = { ...tools.aws, mode, preflightOnly };
    const script = aws.g.buildScript(config);
    const label = `aws: ${mode} preflightOnly=${preflightOnly}`;
    check(`${label} gives valid bash`, validBash(script, `aws-${mode}-${preflightOnly}`));
    check(`${label}: --preflight-only appears only when ticked`, commandLine(script).includes("--preflight-only") === preflightOnly);
    check(`${label}: the script looks for the zip that run writes`,
      script.includes(preflightOnly ? "aws_access_check_*.zip" : "aws_sizing_results_*.zip") &&
      !script.includes(preflightOnly ? "aws_sizing_results_*.zip" : "aws_access_check_*.zip"));
  }
}
check("aws: --preflight-only with --no-csv is refused, as the tool refuses it",
  aws.g.validate({ ...tools.aws, services: ["ec2"], preflightOnly: true, noCsv: true }).some((e) => e.includes("--preflight-only")));
check("aws: --preflight-only drops --keep-artifacts and says so",
  !commandLine(aws.g.buildScript({ ...tools.aws, preflightOnly: true, keepArtifacts: true })).includes("--keep-artifacts") &&
  aws.g.buildNotes({ ...tools.aws, preflightOnly: true, keepArtifacts: true }).some((n) => n.includes("--keep-artifacts has no effect")));

const zipNames = { azure: ["azure_access_check_*.zip", "azure_sizing_results_*.zip"], gcp: ["gcp_access_check_*.zip", "gcp_sizing_results_*.zip"] };
for (const name of ["azure", "gcp"]) {
  const { html, g } = load(name);
  const [accessZip, resultsZip] = zipNames[name];
  check(`${name}: the preflight-only box is not ticked by default`, !/id="preflightOnly"[^>]*checked/.test(html));
  for (const preflightOnly of [false, true]) {
    const script = g.buildScript({ ...tools[name], preflightOnly });
    const label = `${name}: preflightOnly=${preflightOnly}`;
    check(`${label} gives valid bash`, validBash(script, `${name}-preflight-${preflightOnly}`));
    check(`${label}: --preflight-only appears only when ticked`, commandLine(script).includes("--preflight-only") === preflightOnly);
    check(`${label}: the script looks for the zip that run writes`,
      script.includes(preflightOnly ? accessZip : resultsZip) && !script.includes(preflightOnly ? resultsZip : accessZip));
  }
  for (const other of ["noCsv", "mock"]) {
    check(`${name}: --preflight-only with ${other} is refused, as the tool refuses it`,
      g.validate({ ...tools[name], preflightOnly: true, [other]: true }).some((e) => e.includes("--preflight-only")));
  }
}
const azureGuide = load("azure").g;
check("azure: --preflight-only drops --keep-artifacts and says so",
  !commandLine(azureGuide.buildScript({ ...tools.azure, preflightOnly: true, keepArtifacts: true })).includes("--keep-artifacts") &&
  azureGuide.buildNotes({ ...tools.azure, preflightOnly: true, keepArtifacts: true }).some((n) => n.includes("--keep-artifacts has no effect")));

const azure = load("azure");
check("azure: there is no optional install box; every collector's package is in requirements.txt", !/id="parity"/.test(azure.html));
check("azure: the script installs requirements.txt and nothing else",
  azure.g.buildScript(tools.azure).includes("pip install -q -r requirements.txt") && !azure.g.buildScript(tools.azure).includes("requirements-parity.txt"));
check("azure: the notes no longer offer an optional install", !azure.g.buildNotes(tools.azure).join("\n").includes("optional install"));
check("azure: --skip-postgresql is in the command only when ticked",
  commandLine(azure.g.buildScript({ ...tools.azure, skipPostgres: true })).includes("--skip-postgresql") &&
  !commandLine(azure.g.buildScript({ ...tools.azure })).includes("--skip-postgresql"));
const ID = "11111111-1111-1111-1111-111111111111";
const subs = azure.g.buildScript({ ...tools.azure, mode: "subs", subs: ID });
check("azure: --subs mode gives valid bash", validBash(subs, "azure-subs"));
check("azure: --subs mode lists the IDs it will scan and checks each against az", subs.includes(`for id in ${ID}; do`) && subs.includes('az account show --subscription "$id"'));
for (const mode of ["current", "all"]) {
  check(`azure: ${mode} mode has no subscription listing`, !azure.g.buildScript({ ...tools.azure, mode }).includes("for id in"));
}

// Where OUT_DIR points when the script is run from another folder: the script's lines up to OUT_DIR.
function outDirOf(script, label) {
  const dir = path.join(tmp, `script-${label}`);
  fs.mkdirSync(dir, { recursive: true });
  const lines = script.split("\n").filter((l) => l.startsWith("SCRIPT_DIR=") || l.startsWith("OUT_DIR="));
  const file = path.join(dir, "run.sh");
  fs.writeFileSync(file, [...lines, 'printf "%s" "$OUT_DIR"'].join("\n"));
  return { got: spawnSync("bash", [file], { cwd: os.homedir(), encoding: "utf8" }).stdout, dir };
}

const awsModes = {
  single: {},
  sso: { ssoUrl: "https://example.awsapps.com/start", roleName: "ReadOnlyAccess" },
  org: {},
  cross: { crossRole: "R", accounts: "111111111111" },
  profiles: { profiles: "prod" },
  allprofiles: {},
};
const outCases = [
  { name: aws.g, tool: "aws", configs: Object.entries(awsModes).map(([mode, extra]) => [mode, { ...tools.aws, mode, ...extra }]) },
  { name: load("azure").g, tool: "azure", configs: [["current", tools.azure]] },
  { name: load("gcp").g, tool: "gcp", configs: [["current", tools.gcp]] },
];
for (const { name: g, tool, configs } of outCases) {
  for (const [mode, config] of configs) {
    const label = `${tool}: ${mode} mode`;
    const script = g.buildScript(config);
    check(`${label} passes the output folder to the tool`, commandLine(script).includes('--output "$OUT_DIR"'));
    check(`${label} looks for the zip in the output folder`, script.includes('ZIP="$(ls -t "$OUT_DIR"/'));
    for (const [outDir, expect] of [["./output", (d) => path.join(d, "output")], ["./a/b/", (d) => path.join(d, "a/b")], ["/srv/sizing", () => "/srv/sizing"]]) {
      const { got, dir } = outDirOf(g.buildScript({ ...config, outDir }), `${tool}-${mode}-${outDir.replace(/\W/g, "_")}`);
      check(`${label}: output directory ${outDir} is ${outDir.startsWith("/") ? "kept as given" : "next to the script"}`, got === expect(dir));
    }
  }
}
check("aws: SSO mode needs a permission set, as the tool does",
  aws.g.validate({ ...tools.aws, services: ["ec2"], mode: "sso", roleName: "" }).some((e) => e.includes("--role-name")) &&
  aws.g.validate({ ...tools.aws, services: ["ec2"], mode: "sso", roleName: "ReadOnlyAccess" }).length === 0);
check("aws: org mode needs no role name (it defaults to RubrikDiscoveryRole)",
  aws.g.validate({ ...tools.aws, services: ["ec2"], mode: "org" }).length === 0);
check("aws: the output directory is required, as in the Azure and GCP guides",
  aws.g.validate({ ...tools.aws, services: ["ec2"], outDir: "" }).some((e) => e.includes("output directory")));

check("azure: the container and Key Vault boxes are not ticked by default",
  !/id="getContainerDetails"[^>]*checked/.test(azure.html) && !/id="getKeyVaultAmounts"[^>]*checked/.test(azure.html));
for (const [box, flag, note] of [
  ["getContainerDetails", "--get-container-details", "Storage Blob Data Reader"],
  ["getKeyVaultAmounts", "--get-key-vault-amounts", "Key Vault Reader"],
]) {
  const on = azure.g.buildScript({ ...tools.azure, [box]: true });
  check(`azure: ${flag} is in the command only when ticked`,
    commandLine(on).includes(flag) && !commandLine(azure.g.buildScript(tools.azure)).includes(flag));
  check(`azure: ${flag} gives valid bash`, validBash(on, `azure-${box}`));
  check(`azure: ${flag} says which role it needs`, azure.g.buildNotes({ ...tools.azure, [box]: true }).join(" ").includes(note));
}
check("azure: --get-container-details is left out with --skip-storage-accounts, and says so",
  !commandLine(azure.g.buildScript({ ...tools.azure, getContainerDetails: true, skipStorage: true })).includes("--get-container-details") &&
  azure.g.buildNotes({ ...tools.azure, getContainerDetails: true, skipStorage: true }).join(" ").includes("left out of the command"));

const examples = require("./examples/make_examples.js");
for (const [name, text] of Object.entries(examples.expected())) {
  const current = fs.readFileSync(path.join(__dirname, "examples", name), "utf8");
  check(`examples/${name} is what its guide generates now (run: node examples/make_examples.js)`, current === text);
  check(`examples/${name} gives valid bash`, validBash(current, `example-${name}`));
}

let failed = 0;
for (const [name, ok] of results) {
  console.log(`${ok ? "ok" : "FAIL"} ${name}`);
  if (!ok) failed += 1;
}
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
