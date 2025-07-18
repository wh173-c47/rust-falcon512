 const fs = require("fs");
const path = require("path");

const baseDir = "./";
const samplesFile = path.join(baseDir, "falcon512_samples.json");
const distancesFile = path.join(baseDir, "distances.json");

const baseOutputFilePrefix = "falcon512_tests_";

const samples = JSON.parse(fs.readFileSync(samplesFile, "utf8"));
const expected = JSON.parse(fs.readFileSync(distancesFile, "utf8"));

const testsPerFile = 10;
const numFiles = Math.ceil(samples.length / testsPerFile);

const rustPreamble = `
#[cfg(test)]
pub mod tests {
    use crate::{falcon512::pk_to_ntt_fmt, tests::test_utils::verify_distance};
`;

const rustPostamble = `
}
`;

for (let fileIndex = 0; fileIndex < numFiles; fileIndex++) {
  const startIndex = fileIndex * testsPerFile;
  const endIndex = Math.min((fileIndex + 1) * testsPerFile, samples.length);
  const fileName = `${baseOutputFilePrefix}${fileIndex}.rs`;
  const writeStream = fs.createWriteStream(fileName);

  writeStream.write(rustPreamble);

  for (let i = startIndex; i < endIndex; i++) {
    const sample = samples[i];
    const nonceMsg = sample.nonce_msg.join(", ");
    const sig = sample.sig.join(", ");
    const pk = sample.pk.join(", ");
    const expectedRes = expected[i];

    writeStream.write(`

    #[test]
    pub fn nist_test_verify_${i}() {
        let nonce_msg = vec![${nonceMsg}];
        let sig = vec![${sig}];
        let pk = [${pk}];
        let pk_ntt_fmt = pk_to_ntt_fmt(&pk);

        let res = verify_distance(nonce_msg, sig, &pk_ntt_fmt);
        assert_eq!(res, ${expectedRes});
    }
`);
  }

  writeStream.write(rustPostamble);
  writeStream.end();

  console.log(`Rust test file generated: ${fileName}`);
}
