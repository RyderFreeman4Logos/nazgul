//! Generate and audit the signed, synthetic ballots for Nazgul bounty 001.

use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use digest::{generic_array::typenum::U64, Digest};
use nazgul::blake3_compat::Blake3_512;
use nazgul::blsag::BLSAG;
use nazgul::keypair::KeyPair;
use nazgul::ring::{PreparedRing, Ring};
use nazgul::scalar::{RistrettoPoint, Scalar};
use nazgul::traits::{LocalByteConvertible, VerifyRef};
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use zeroize::Zeroizing;

const NAMES: &str = include_str!("../bounties/001/names.txt");
const OPTIONS: [&str; 3] = ["opt-like", "opt-unlike", "opt-abstain"];
const COUNTS: [usize; 3] = [60, 20, 20];
const MAX_ROSTER: u64 = 128 * 1024;
const MAX_BALLOT_LINE: u64 = 32 * 1024;

#[derive(Serialize, Deserialize)]
enum Suite {
    #[serde(rename = "sha512")]
    Sha512,
    #[serde(rename = "blake3-512")]
    Blake3,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ballot {
    option: String,
    suite: Suite,
    signature: BLSAG,
    // Every ballot needs a vote signature in the same key-image domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    poll_signature: Option<BLSAG>,
}

fn message(option: &str) -> Vec<u8> {
    [
        b"nazgul-bounty-001\0Does Xi Jinping Look Like Winnie the Pooh?\0",
        option.as_bytes(),
    ]
    .concat()
}

fn sign<H: Digest<OutputSize = U64> + Clone + Default>(
    key: Scalar,
    ring: &Ring,
    prepared: &PreparedRing<H>,
    message: &[u8],
    rng: &mut (impl RngCore + CryptoRng),
    streaming: bool,
) -> Result<BLSAG> {
    Ok(if streaming {
        BLSAG::sign_streaming_with_rng::<H, _>(key, ring, message, rng)?
    } else {
        BLSAG::sign_with_rng::<H, _>(key, ring, Some(prepared), message, rng)?
    })
}

fn verify<H: Digest<OutputSize = U64> + Clone + Default>(
    signature: &BLSAG,
    ring: &Ring,
    prepared: &PreparedRing<H>,
    message: &[u8],
) -> Result<()> {
    ensure!(
        BLSAG::verify::<H>(signature, ring, Some(prepared), message),
        "invalid signature (prepared verifier)"
    );
    ensure!(
        BLSAG::verify_streaming::<H>(signature, ring, message),
        "invalid signature (streaming verifier)"
    );
    Ok(())
}

fn write_round(
    names: &str,
    counts: [usize; 3],
    rng: &mut (impl RngCore + CryptoRng),
    mut roster: impl Write,
    mut ballots: impl Write,
) -> Result<Zeroizing<String>> {
    let mut assignments = Vec::new();
    for (option, count) in OPTIONS.into_iter().zip(counts) {
        assignments.extend(std::iter::repeat_n(option, count));
    }
    let names: Vec<_> = names.lines().collect();
    ensure!(
        names.len() == assignments.len()
            && names.iter().collect::<HashSet<_>>().len() == names.len()
            && names
                .iter()
                .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic() || b == b' ')),
        "invalid synthetic roster"
    );
    assignments.shuffle(rng);
    let mut voters: Vec<_> = names
        .into_iter()
        .zip(assignments)
        .map(|(name, option)| {
            let pair = KeyPair::generate(rng);
            (pair.public().to_base58(), name, option, pair)
        })
        .collect();
    voters.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let ring = Ring::new(voters.iter().map(|v| *v.3.public()).collect());
    let sha = ring.precompute::<Sha512>();
    let blake = ring.precompute::<Blake3_512>();
    let mut answer = Zeroizing::new(String::new());
    for (public_key, name, option, _) in &voters {
        writeln!(roster, "{name},{public_key}")?;
        if !answer.is_empty() {
            answer.push('\n');
        }
        answer.push_str(name);
        answer.push(',');
        answer.push_str(option);
    }
    roster.flush()?;

    // Publication order must be independent of both the secret assignment and the roster order.
    voters.shuffle(rng);
    for (index, (_, _, option, pair)) in voters.into_iter().enumerate() {
        let secret = pair.secret().context("missing generated key")?;
        let message = message(option);
        let streaming = index % 4 >= 2;
        let vote = sign(*secret, &ring, &sha, &message, rng, streaming)?;
        let (suite, signature, poll_signature) = if index.is_multiple_of(2) {
            (Suite::Sha512, vote, None)
        } else {
            let sample = sign(*secret, &ring, &blake, &message, rng, streaming)?;
            (Suite::Blake3, sample, Some(vote))
        };
        let ballot = Ballot {
            option: option.to_owned(),
            suite,
            signature,
            poll_signature,
        };
        serde_json::to_writer(&mut ballots, &ballot)?;
        writeln!(ballots)?;
    }
    ballots.flush()?;
    Ok(answer)
}

fn read_ring(roster: impl Read, names: &str) -> Result<Ring> {
    let mut text = String::new();
    roster.take(MAX_ROSTER + 1).read_to_string(&mut text)?;
    ensure!(text.len() as u64 <= MAX_ROSTER, "oversized roster");
    let mut missing: HashSet<_> = names.lines().collect();
    let mut points = Vec::with_capacity(missing.len());
    let mut previous = "";
    for row in text.lines() {
        let (name, key) = row.split_once(',').context("invalid roster row")?;
        ensure!(missing.remove(name), "unknown or repeated name");
        ensure!(
            key.len() <= 44 && previous < key,
            "invalid key length, order or duplicate"
        );
        let point = RistrettoPoint::from_base58(key.to_owned())?;
        ensure!(point != RistrettoPoint::default(), "identity public key");
        points.push(point);
        previous = key;
    }
    ensure!(missing.is_empty(), "incomplete roster");
    Ok(Ring::new(points))
}

fn audit_round(
    roster: impl Read,
    mut ballots: impl BufRead,
    names: &str,
    mut remaining: [usize; 3],
) -> Result<()> {
    let ring = read_ring(roster, names)?;
    let sha = ring.precompute::<Sha512>();
    let blake = ring.precompute::<Blake3_512>();
    let mut images = HashSet::with_capacity(ring.len());
    let mut blake_ballots = 0;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes = ballots
            .by_ref()
            .take(MAX_BALLOT_LINE + 1)
            .read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        ensure!(bytes as u64 <= MAX_BALLOT_LINE, "oversized ballot");
        let ballot: Ballot = serde_json::from_str(&line)?;
        let index = OPTIONS
            .iter()
            .position(|id| *id == ballot.option)
            .context("unknown option")?;
        let count = &mut remaining[index];
        *count = count
            .checked_sub(1)
            .context("too many ballots for option")?;
        let message = message(&ballot.option);
        let vote = match (ballot.suite, ballot.poll_signature.as_ref()) {
            (Suite::Sha512, None) => &ballot.signature,
            (Suite::Blake3, Some(poll_signature)) => {
                verify(&ballot.signature, &ring, &blake, &message)?;
                blake_ballots += 1;
                poll_signature
            }
            _ => bail!("unexpected vote signature fields for this suite"),
        };
        verify(vote, &ring, &sha, &message)?;
        let image = vote.key_image();
        ensure!(
            *image != RistrettoPoint::default() && images.insert(image.to_bytes()),
            "invalid or duplicate vote key image"
        );
    }
    ensure!(
        remaining == [0; 3] && images.len() == ring.len(),
        "incomplete tally"
    );
    ensure!(blake_ballots == ring.len() / 2, "incorrect suite counts");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [command, directory] = args.as_slice() else {
        bail!("usage: bounty_ballots (generate|audit) PUBLIC_DIR")
    };
    let dir = Path::new(directory);
    let roster = dir.join("voters.csv");
    let ballots = dir.join("ballots.jsonl");
    if command == "generate" {
        let destination = File::from(io::stdout().as_fd().try_clone_to_owned()?)
            .metadata()?
            .file_type();
        ensure!(
            destination.is_fifo() || destination.is_socket(),
            "pipe the private answer directly to the organizer"
        );
        let roster = BufWriter::new(File::create_new(roster)?);
        let ballots = BufWriter::new(File::create_new(ballots)?);
        let answer = write_round(NAMES, COUNTS, &mut OsRng, roster, ballots)?;
        let mut output = io::stdout().lock();
        output.write_all(answer.as_bytes())?;
        output.flush()?;
    } else if command == "audit" {
        audit_round(
            File::open(roster)?,
            BufReader::new(File::open(ballots)?),
            NAMES,
            COUNTS,
        )?;
        eprintln!(
            "Verified 100 ballots, 50 per suite, with both verifiers, distinct vote key images and the 60/20/20 tally."
        );
    } else {
        bail!("unknown command; use generate or audit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn published_ballots_verify_and_bind_the_option() -> Result<()> {
        let names = "Alice\nBob\nCarol\nDavid\nEve\nFrank\nGrace\nHelen\nIvan";
        let counts = [5, 2, 2];
        let mut roster = Vec::new();
        let mut ballots = Vec::new();
        let answer = write_round(
            names,
            counts,
            &mut ChaCha20Rng::from_seed([42; 32]),
            &mut roster,
            &mut ballots,
        )?;
        audit_round(&roster[..], &ballots[..], names, counts)?;
        let roster_names: Vec<_> = std::str::from_utf8(&roster)?
            .lines()
            .filter_map(|r| r.split_once(',').map(|v| v.0))
            .collect();
        let answer_names: Vec<_> = answer
            .lines()
            .filter_map(|r| r.split_once(',').map(|v| v.0))
            .collect();
        assert_eq!(answer_names, roster_names);
        assert!(!answer.ends_with('\n'));
        let published = std::str::from_utf8(&ballots)?;
        let published_options: Vec<_> = published
            .lines()
            .map(|line| serde_json::from_str::<Ballot>(line).map(|b| b.option))
            .collect::<serde_json::Result<_>>()?;
        let answer_options: Vec<_> = answer
            .lines()
            .filter_map(|r| r.split_once(',').map(|v| v.1))
            .collect();
        assert_ne!(published_options, answer_options);
        let changed = published.replace("opt-like", "opt-abstain");
        assert!(
            audit_round(&roster[..], changed.as_bytes(), names, [0, 2, 7])
                .unwrap_err()
                .to_string()
                .contains("invalid signature")
        );
        Ok(())
    }

    #[test]
    fn the_vote_signature_checks_duplicates_across_sample_suites() -> Result<()> {
        let names = "A\nB\nC\nD";
        let counts = [4, 0, 0];
        let (mut roster, mut ballots) = (Vec::new(), Vec::new());
        write_round(
            names,
            counts,
            &mut ChaCha20Rng::from_seed([9; 32]),
            &mut roster,
            &mut ballots,
        )?;
        let mut rows: Vec<Ballot> = serde_json::Deserializer::from_slice(&ballots)
            .into_iter()
            .collect::<serde_json::Result<_>>()?;
        assert!(matches!(rows[0].suite, Suite::Sha512));
        assert!(matches!(rows[1].suite, Suite::Blake3));
        rows[1].poll_signature = Some(rows[0].signature.clone());
        let mut duplicate = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut duplicate, &row)?;
            writeln!(duplicate)?;
        }
        assert!(audit_round(&roster[..], &duplicate[..], names, counts)
            .unwrap_err()
            .to_string()
            .contains("duplicate vote key image"));
        Ok(())
    }
}
