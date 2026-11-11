// Writes the example scripts from the run guides, so they are exactly what a guide produces with
// placeholder IDs. Run: node make_examples.js. check_guides.js fails when an example is out of date.

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const GUIDES = path.join(__dirname, "..");

function load(name) {
  const html = fs.readFileSync(path.join(GUIDES, `${name}-run-guide.html`), "utf8");
  const block = html.split("<script>").map((p) => p.split("</script>")[0]).find((p) => p.includes("function buildScript"));
  const context = { module: { exports: {} }, console };
  vm.runInNewContext(block, context);
  return context.module.exports;
}

// The settings each example is built with. The IDs are placeholders: run as it is, an example fails at sign-in or
// finds nothing to scan.
const EXAMPLES = {
  aws: {
    config: {
      mode: "sso", ssoUrl: "https://YOUR-ORG.awsapps.com/start", roleName: "YOUR_PERMISSION_SET",
      accounts: "ACCOUNT_ID_1,ACCOUNT_ID_2", services: [], noCost: true, outDir: "./output", cloud: "auto",
    },
    replace: "YOUR-ORG, YOUR_PERMISSION_SET and ACCOUNT_ID_1,ACCOUNT_ID_2",
  },
  azure: {
    config: {
      mode: "subs", subs: "SUBSCRIPTION_ID_1,SUBSCRIPTION_ID_2", cloud: "auto", noCost: true, noDevops: true,
      outDir: "./output",
    },
    replace: "SUBSCRIPTION_ID_1,SUBSCRIPTION_ID_2",
  },
  gcp: {
    config: {
      mode: "projects", projects: "PROJECT_ID_1,PROJECT_ID_2", workers: "8", cloud: "auto", outDir: "./output",
      collectors: ["asset", "compute", "storage", "database", "bigquery", "backup"],
    },
    replace: "PROJECT_ID_1,PROJECT_ID_2",
  },
};

function expected() {
  const out = {};
  for (const [cloud, { config, replace }] of Object.entries(EXAMPLES)) {
    const lines = load(cloud).buildScript(config).split("\n");
    lines.splice(
      2,
      0,
      `# EXAMPLE: replace ${replace} with your own values`,
      `# before running it, or generate your own script from ${cloud}-run-guide.html.`,
    );
    out[`run-${cloud}-sizing.sh`] = lines.join("\n");
  }
  return out;
}

if (require.main === module) {
  for (const [name, text] of Object.entries(expected())) {
    fs.writeFileSync(path.join(__dirname, name), text);
    console.log(`wrote ${name}`);
  }
}

module.exports = { EXAMPLES, expected };
