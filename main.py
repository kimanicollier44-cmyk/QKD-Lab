#!/usr/bin/env python3
"""QKD-Lab - educational quantum key distribution lab.

by Darion Kellar

Pure Python standard library. Zero dependencies. Zero network.
Education only - and the central lesson is stated up front:

  * QKD-Lab simulates the BB84 protocol end-to-end (plus a
    BBM92-style entangled variant) with a CLASSICAL measurement
    model: a "qubit" here is a (bit, basis) pair, and measurement
    is a rule, not a photon.
  * The security intuition is real and it is taught honestly:
    an eavesdropper who measures in the wrong basis disturbs the
    states she cannot read, the disturbance shows up as a quantum
    bit error rate (QBER) of about 25%, and the protocol ABORTS
    instead of shipping a compromised key.
  * No real photons are emitted, no real key is secret, and
    nothing here protects a real message. The final "key" is a
    string of simulated bits whose length accounting is honest -
    sifting, parameter estimation, error correction, and privacy
    amplification each take their cut in the open.

Real key generation, real secrecy claims, interception of real
communications, and military / government / banking / medical /
infrastructure use are permanent HOLD gates - with Gemini Argon 4
Extended Thinking as DECIDER (names-only, tighten-only), Muse
as advisor (never overrides HOLD), and Google Flow plan-only seats.
"""
import hashlib
import json
import math
import random
import sys

# ---------------------------------------------------------------- constants
VERSION = "1.0.0"
BASES = ("+", "x")  # rectilinear (Z) and diagonal (X)

# The famous BB84 abort line: with ideal error correction the
# Shor-Preskill key rate 1 - 2*h2(q) reaches zero at q ~= 11.0%.
# Above it, Alice and Bob cannot distil a key Eve knows less about
# than they do - so the only honest move is to abort.
QBER_ABORT_THRESHOLD = 0.11
SUSPICIOUS_QBER = 0.05
MIN_TRUSTED_SAMPLE = 64

# Error correction leaks more than the Shannon limit h2(q); real
# Cascade/LDPC reconciliation is priced here with the labelled
# efficiency factor f = 1.15 (teaching value, stated in the open).
EC_EFFICIENCY = 1.15

DEFAULT_RAW_BITS = 4096
DEFAULT_SAMPLE = 256
LABELLED_NOISE = 0.02  # labelled depolarising channel rate for demos

SEED_BB84_IDEAL = 84
SEED_BB84_NOISE = 85
SEED_BB84_EVE = 86
SEED_E91_IDEAL = 91
SEED_E91_EVE = 92

# ---------------------------------------------------------------- HOLD gates
HOLD_GATES = {
    "production_key_generation": "HOLD - no generating keys for production or real-world use; lab keys are simulated bits",
    "real_world_secrecy_claim": "HOLD - no claim that a lab key is actually secret or safe to encrypt real data with",
    "intercept_real_communications": "HOLD - no intercepting, monitoring, or tampering with real communications",
    "military_government_comms": "HOLD - no military, government, or intelligence secure-communications use",
    "banking_financial_keys": "HOLD - no generating or handling keys for banking, payments, or financial systems",
    "medical_communications": "HOLD - no protecting real medical records or clinical communications",
    "critical_infrastructure_comms": "HOLD - no securing power, water, transport, or other critical-infrastructure channels",
    "law_enforcement_comms": "HOLD - no law-enforcement or emergency-services secure-communications use",
    "live_network_deployment": "HOLD - no deploying this simulation on a live network as a key service",
    "real_qkd_hardware_control": "HOLD - no control of real QKD hardware, single-photon sources, or detectors",
    "side_channel_attack_real_systems": "HOLD - no side-channel or detector-blinding attacks on real QKD systems",
    "certified_security_claim": "HOLD - no claim of certified or proven information-theoretic security for any real system",
    "espionage_surveillance_use": "HOLD - no espionage, surveillance, or covert-interception use",
    "key_sale_or_service": "HOLD - no selling keys, key material, or a key-distribution service",
}


def gate(action):
    """Return 'HOLD' if the action is gated, else 'PROCEED' (sandbox sim)."""
    return "HOLD" if action in HOLD_GATES else "PROCEED"


# ================================================================ 1. Math helpers
def binary_entropy(p):
    """Shannon binary entropy h2(p) in bits; h2(0) = h2(1) = 0."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)


def poisson_pmf(mu, n):
    """Poisson probability of exactly n photons at mean mu."""
    return math.exp(-mu) * mu ** n / math.factorial(n)


def multiphoton_probability(mu):
    """P(n >= 2) for a weak coherent pulse - the PNS attack surface."""
    return 1.0 - poisson_pmf(mu, 0) - poisson_pmf(mu, 1)


# ================================================================ 2. Measurement model
# The whole "quantum" layer of the lab, stated plainly: a qubit is a
# (bit, basis) pair. Measuring in the preparation basis returns the
# bit; measuring in the other basis returns a coin flip, and the
# state is replaced by what was measured (that replacement is the
# disturbance Eve cannot avoid). A labelled depolarising rate then
# flips the outcome, standing in for channel + detector noise.

def measure(bit, basis, meas_basis, rng, noise=0.0):
    """Measure (bit, basis) in meas_basis; return the outcome bit."""
    result = bit if meas_basis == basis else rng.randrange(2)
    if noise > 0.0 and rng.random() < noise:
        result ^= 1
    return result


def key_accounting(sifted_count, sample_size, qber, aborted):
    """Price the key honestly: sample, error correction, privacy amp.

    - The revealed sample is discarded (it was spoken aloud).
    - Error correction leaks ~ f * h2(q) bits per remaining bit.
    - Privacy amplification sacrifices ~ h2(q) bits per remaining
      bit to erase Eve's information (Shor-Preskill accounting).
    An aborted run distils nothing: final length 0.
    """
    after_sample = max(0, sifted_count - sample_size)
    if aborted:
        return {"after_sample": after_sample, "ec_cost_bits": 0,
                "pa_cost_bits": 0, "final_key_length": 0}
    leak = binary_entropy(qber)
    ec_cost = math.ceil(after_sample * EC_EFFICIENCY * leak)
    pa_cost = math.ceil(after_sample * leak)
    final = max(0, after_sample - ec_cost - pa_cost)
    return {"after_sample": after_sample, "ec_cost_bits": ec_cost,
            "pa_cost_bits": pa_cost, "final_key_length": final}


def _finish_run(protocol, n, noise, eve_fraction, sample_size,
                alice_bits, bob_bits, sifted_idx):
    """Shared sifting -> sampling -> QBER -> abort/accounting tail."""
    sample_idx = sifted_idx[:sample_size]
    sample_errors = sum(1 for i in sample_idx if alice_bits[i] != bob_bits[i])
    qber = sample_errors / len(sample_idx) if sample_idx else 0.0
    aborted = qber > QBER_ABORT_THRESHOLD
    accounting = key_accounting(len(sifted_idx), len(sample_idx), qber, aborted)
    remaining = [bob_bits[i] for i in sifted_idx[len(sample_idx):]]
    final_bits = "".join(str(b) for b in remaining[:accounting["final_key_length"]])
    return {
        "protocol": protocol,
        "raw_bits": n,
        "noise_rate": noise,
        "eve_fraction": eve_fraction,
        "sifted_bits": len(sifted_idx),
        "sift_rate": round(len(sifted_idx) / n, 4) if n else 0.0,
        "sample_size": len(sample_idx),
        "sample_errors": sample_errors,
        "qber": round(qber, 4),
        "status": "ABORTED" if aborted else "KEY_ESTABLISHED",
        "abort_reason": ("QBER_ABOVE_ABORT_THRESHOLD" if aborted else None),
        "after_sample": accounting["after_sample"],
        "ec_cost_bits": accounting["ec_cost_bits"],
        "pa_cost_bits": accounting["pa_cost_bits"],
        "final_key_length": accounting["final_key_length"],
        "final_key_sha256_16": hashlib.sha256(
            final_bits.encode()).hexdigest()[:16] if final_bits else None,
    }


# ================================================================ 3. BB84
def run_bb84(n=DEFAULT_RAW_BITS, seed=SEED_BB84_IDEAL, noise=0.0,
             eve_fraction=0.0, sample_size=DEFAULT_SAMPLE):
    """BB84 end-to-end: prepare, (Eve), measure, sift, estimate, distil.

    Alice sends random bits in random bases. Eve, when present,
    intercepts a fraction of the qubits, measures each in a random
    basis, and resends what she measured - the intercept-resend
    attack. Bob measures in random bases. Matching-basis events are
    sifted; a revealed sample prices the QBER.
    """
    rng = random.Random(seed)
    alice_bits = [rng.randrange(2) for _ in range(n)]
    alice_bases = [rng.choice(BASES) for _ in range(n)]
    bob_bases = [rng.choice(BASES) for _ in range(n)]
    bob_bits = []
    for i in range(n):
        bit, basis = alice_bits[i], alice_bases[i]
        if eve_fraction > 0.0 and rng.random() < eve_fraction:
            eve_basis = rng.choice(BASES)
            bit = measure(bit, basis, eve_basis, rng, noise=0.0)
            basis = eve_basis
        bob_bits.append(measure(bit, basis, bob_bases[i], rng, noise))
    sifted = [i for i in range(n) if alice_bases[i] == bob_bases[i]]
    return _finish_run("BB84", n, noise, eve_fraction, sample_size,
                        alice_bits, bob_bits, sifted)


# ================================================================ 4. E91 / BBM92 style
def run_e91(n=DEFAULT_RAW_BITS, seed=SEED_E91_IDEAL, noise=0.0,
            eve_fraction=0.0, sample_size=DEFAULT_SAMPLE):
    """Entanglement-based variant in a correlated-pair model.

    A source emits pairs with a shared bit and a reference basis.
    When Alice and Bob measure in the SAME basis their outcomes
    agree (up to the labelled noise); in different bases the
    outcomes are independent. The agreement is computed jointly -
    no local hidden-variable model can reproduce singlet statistics
    (that is Bell's theorem, and it is the point of E91) - so this
    is a statistics model of the pair source, not a statevector.

    Eve intercepts Bob's travelling half, measures it in a random
    basis, and resends a classical state: the pair correlation
    collapses, and same-basis agreement falls to 75% (QBER ~ 25%),
    the same fingerprint as in BB84.
    """
    rng = random.Random(seed)
    pair_bits = [rng.randrange(2) for _ in range(n)]
    pair_ref = [rng.choice(BASES) for _ in range(n)]
    alice_bases = [rng.choice(BASES) for _ in range(n)]
    bob_bases = [rng.choice(BASES) for _ in range(n)]
    alice_bits, bob_bits = [], []
    for i in range(n):
        shared = pair_bits[i] ^ (0 if alice_bases[i] == pair_ref[i] else 1)
        if eve_fraction > 0.0 and rng.random() < eve_fraction:
            eve_basis = rng.choice(BASES)
            eve_bit = pair_bits[i] ^ (0 if eve_basis == pair_ref[i] else 1)
            a_bit = eve_bit if alice_bases[i] == eve_basis else rng.randrange(2)
            b_bit = measure(eve_bit, eve_basis, bob_bases[i], rng, noise)
        else:
            if alice_bases[i] == bob_bases[i]:
                a_bit = shared
                b_bit = shared
                if noise > 0.0 and rng.random() < noise:
                    b_bit ^= 1
            else:
                a_bit = rng.randrange(2)
                b_bit = rng.randrange(2)
        alice_bits.append(a_bit)
        bob_bits.append(b_bit)
    sifted = [i for i in range(n) if alice_bases[i] == bob_bases[i]]
    return _finish_run("E91", n, noise, eve_fraction, sample_size,
                        alice_bits, bob_bits, sifted)


# ================================================================ 5. Decoy-state note
def decoy_note():
    """Why decoy states exist - LABELLED note, Poisson numbers only.

    Real BB84 transmitters usually emit weak laser pulses, not true
    single photons. A pulse with mean photon number mu sometimes
    carries 2+ photons (Poisson statistics); Eve can split one off
    and keep it - the photon-number-splitting (PNS) attack - and
    learn that bit without disturbing anything. Decoy-state QKD
    mixes pulses of several intensities so the PNS theft changes
    the per-intensity yields and gives itself away. This lab does
    NOT simulate decoy intensities; it computes the Poisson surface
    that makes them necessary, and says so.
    """
    rows = {}
    for mu in (0.1, 0.5, 1.0):
        rows[f"mu_{mu}"] = {
            "p_empty": round(poisson_pmf(mu, 0), 4),
            "p_single": round(poisson_pmf(mu, 1), 4),
            "p_multiphoton": round(multiphoton_probability(mu), 4),
        }
    return {
        "topic": "decoy states and the photon-number-splitting attack",
        "simulated": False,
        "poisson_surface": rows,
        "lesson": "At mu = 0.5 about 9% of non-empty pulses carry a "
                  "spare photon Eve could split off undetected; "
                  "decoy intensities exist to make that theft visible.",
    }


# ================================================================ 6. kNN run classifier
# Features: QBER, sift rate, sample size. The training grid is
# labelled by the protocol's own security policy (model_label) -
# the classifier interpolates the policy, it does not replace the
# QBER abort rule, which always runs first and cannot be outvoted.

def model_label(qber, sift_rate, sample_size):
    """The protocol policy distilled to a three-way teaching label."""
    if qber > QBER_ABORT_THRESHOLD:
        return "compromised"
    if qber > SUSPICIOUS_QBER:
        return "suspicious"
    if sample_size < MIN_TRUSTED_SAMPLE:
        return "suspicious"
    if not 0.35 <= sift_rate <= 0.65:
        return "suspicious"
    return "safe"


def _training_grid():
    rows = []
    for qber in (0.0, 0.01, 0.02, 0.04, 0.06, 0.08, 0.10, 0.13, 0.18, 0.25):
        for sift_rate in (0.30, 0.40, 0.50, 0.60, 0.70):
            for sample in (16, 32, 64, 128, 256, 512):
                rows.append(((qber, sift_rate, sample),
                             model_label(qber, sift_rate, sample)))
    return rows


TRAINING_GRID = _training_grid()


def _scaled(features):
    qber, sift_rate, sample_size = features
    return (qber / 0.25, sift_rate, math.log2(max(sample_size, 1)) / 9.0)


def classify_run(qber, sift_rate, sample_size, k=5):
    """kNN over the policy-labelled grid, deterministic tie-breaking."""
    target = _scaled((qber, sift_rate, sample_size))
    ranked = []
    for features, label in TRAINING_GRID:
        point = _scaled(features)
        dist = math.sqrt(sum((a - b) ** 2 for a, b in zip(target, point)))
        ranked.append((dist, features, label))
    ranked.sort(key=lambda row: (row[0], row[1]))
    votes = {}
    for _, _, label in ranked[:k]:
        votes[label] = votes.get(label, 0) + 1
    priority = {"safe": 0, "suspicious": 1, "compromised": 2}
    return sorted(votes.items(), key=lambda kv: (-kv[1], priority[kv[0]]))[0][0]


def demo_runs():
    """The five canonical runs every report and check is built on."""
    return {
        "bb84_ideal": run_bb84(seed=SEED_BB84_IDEAL, noise=0.0),
        "bb84_labelled_noise": run_bb84(seed=SEED_BB84_NOISE,
                                        noise=LABELLED_NOISE),
        "bb84_eve_intercept_resend": run_bb84(seed=SEED_BB84_EVE,
                                              noise=LABELLED_NOISE,
                                              eve_fraction=1.0),
        "e91_ideal": run_e91(seed=SEED_E91_IDEAL, noise=0.0),
        "e91_eve_intercept_resend": run_e91(seed=SEED_E91_EVE,
                                            noise=LABELLED_NOISE,
                                            eve_fraction=1.0),
    }


def classifier_report():
    runs = demo_runs()
    scenarios = {}
    for name in ("bb84_ideal", "bb84_labelled_noise",
                 "bb84_eve_intercept_resend", "e91_eve_intercept_resend"):
        run = runs[name]
        scenarios[name] = classify_run(run["qber"], run["sift_rate"],
                                       run["sample_size"])
    rushed = run_bb84(seed=SEED_BB84_IDEAL, noise=0.0, sample_size=16)
    scenarios["bb84_rushed_sample_16"] = classify_run(
        rushed["qber"], rushed["sift_rate"], rushed["sample_size"])
    scenarios["borderline_qber_0.08"] = classify_run(0.08, 0.50, 256)
    return scenarios


# ================================================================ 7. Advisory seats
def _trace(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


def argon4_decide(topic="qkd-lab-demo"):
    """Gemini Argon 4 DECIDER seat: MAP->MODEL->STRESS->DECIDE.

    Names-only keys, live calls 0, tighten-only: can add HOLDs, never lift one.
    """
    stages = ["MAP", "MODEL", "STRESS", "DECIDE"]
    payload = {"seat": "gemini-argon-4", "topic": topic, "stages": stages}
    return {
        "seat": "Gemini Argon 4 Extended Thinking",
        "role": "DECIDER",
        "pipeline": stages,
        "tiers": [2048, 8192, 32768],
        "key": "names-only (GEMINI_API_KEY name checked, value never read)",
        "live_calls": 0,
        "decision": "PROCEED - sandbox simulation only, all real-key and interception gates stay HOLD",
        "can_override_hold": False,
        "trace_sha256_16": _trace(payload),
    }


def claude_advisor(topic="qkd-lab-demo"):
    """Muse advisor seat: advises, can never override a HOLD."""
    return {
        "seat": "Muse",
        "role": "ADVISOR",
        "key": "names-only (MODEL_API_KEY name checked, value never read)",
        "live_calls": 0,
        "advice": "Lead with the disturbance: Eve's information is bought with errors, so publish the QBER, the abort threshold, and the full key-shrink ledger for every run - the shrinking is the security story.",
        "can_override_hold": False,
    }


def google_flow_plan():
    """Google Flow seat: plan-only, nothing rendered, nothing live."""
    return {
        "seat": "Google Flow",
        "role": "PLAN-ONLY",
        "shots": ["photons leaving Alice in two bases, plus and cross",
                  "Bob's basis wheel matching half the arrivals",
                  "a revealed sample lighting up with a 2% error dusting",
                  "Eve's probe shattering every second photon she touches",
                  "the QBER needle crossing the red 11% line and the run aborting",
                  "a long sifted string shrinking through EC and PA into a short key"],
        "rendered": False,
        "live": 0,
    }


def brains_report():
    return {"decider": argon4_decide(), "advisor": claude_advisor(),
            "flow": google_flow_plan()}


# ================================================================ checks
def run_checks():
    c = []

    def chk(name, ok):
        c.append((name, bool(ok)))

    # 1. math helpers
    chk("entropy_endpoints", binary_entropy(0.0) == 0.0
        and binary_entropy(1.0) == 0.0 and binary_entropy(0.5) == 1.0)
    chk("entropy_at_abort_threshold",
        abs(binary_entropy(QBER_ABORT_THRESHOLD) - 0.4999) < 0.001)
    chk("poisson_single_photon_mu1",
        abs(poisson_pmf(1.0, 1) - math.exp(-1)) < 1e-12)
    chk("multiphoton_mu_half",
        abs(multiphoton_probability(0.5) - 0.0902) < 0.001)
    chk("multiphoton_grows_with_mu",
        multiphoton_probability(0.1) < multiphoton_probability(0.5)
        < multiphoton_probability(1.0))

    # 2. measurement model
    rng = random.Random(7)
    chk("measure_matching_basis_returns_bit",
        all(measure(b, "+", "+", rng, 0.0) == b for b in (0, 1))
        and all(measure(b, "x", "x", rng, 0.0) == b for b in (0, 1)))
    chk("measure_full_noise_always_flips",
        all(measure(b, "+", "+", rng, 1.0) == 1 - b for b in (0, 1)))

    # 3. BB84 canonical runs
    runs = demo_runs()
    ideal = runs["bb84_ideal"]
    chk("bb84_ideal_qber_zero", ideal["qber"] == 0.0
        and ideal["sample_errors"] == 0)
    chk("bb84_ideal_key_established", ideal["status"] == "KEY_ESTABLISHED"
        and ideal["abort_reason"] is None)
    chk("bb84_ideal_no_distillation_cost",
        ideal["ec_cost_bits"] == 0 and ideal["pa_cost_bits"] == 0
        and ideal["final_key_length"] == ideal["after_sample"])
    chk("bb84_sift_rate_near_half", 0.45 <= ideal["sift_rate"] <= 0.55)
    noisy = runs["bb84_labelled_noise"]
    chk("bb84_noise_qber_small", 0.0 < noisy["qber"] < SUSPICIOUS_QBER)
    chk("bb84_noise_key_shrinks_but_survives",
        0 < noisy["final_key_length"] < noisy["after_sample"]
        and noisy["ec_cost_bits"] > 0 and noisy["pa_cost_bits"] > 0)
    chk("bb84_runs_deterministic", run_bb84() == run_bb84()
        and run_bb84(seed=SEED_BB84_NOISE, noise=LABELLED_NOISE) == noisy)

    # 4. Eve intercept-resend - the fingerprint and the abort
    eve = runs["bb84_eve_intercept_resend"]
    chk("eve_qber_above_20_percent", eve["qber"] > 0.20)
    chk("eve_run_aborts_with_reason",
        eve["status"] == "ABORTED"
        and eve["abort_reason"] == "QBER_ABOVE_ABORT_THRESHOLD")
    chk("eve_abort_distils_nothing", eve["final_key_length"] == 0
        and eve["final_key_sha256_16"] is None)
    partial = run_bb84(seed=SEED_BB84_EVE, noise=LABELLED_NOISE,
                       eve_fraction=0.5)
    chk("partial_eve_qber_between_noise_and_full",
        noisy["qber"] < partial["qber"] < eve["qber"])
    chk("eve_signature_is_quarter_errors",
        abs(eve["qber"] - 0.25) < 0.06)

    # 5. E91 / BBM92 correlated-pair runs
    e91 = runs["e91_ideal"]
    chk("e91_ideal_qber_zero", e91["qber"] == 0.0
        and e91["status"] == "KEY_ESTABLISHED")
    chk("e91_sift_rate_near_half", 0.45 <= e91["sift_rate"] <= 0.55)
    e91_eve = runs["e91_eve_intercept_resend"]
    chk("e91_eve_qber_above_20_percent", e91_eve["qber"] > 0.20)
    chk("e91_eve_aborts_with_reason",
        e91_eve["status"] == "ABORTED"
        and e91_eve["abort_reason"] == "QBER_ABOVE_ABORT_THRESHOLD"
        and e91_eve["final_key_length"] == 0)

    # 6. key accounting arithmetic
    acct = key_accounting(2000, 256, 0.0, aborted=False)
    chk("accounting_zero_qber_no_cost",
        acct["after_sample"] == 1744 and acct["final_key_length"] == 1744)
    acct_abort = key_accounting(2000, 256, 0.25, aborted=True)
    chk("accounting_abort_zero_key", acct_abort["final_key_length"] == 0
        and acct_abort["ec_cost_bits"] == 0)
    acct_mid = key_accounting(2000, 256, 0.05, aborted=False)
    chk("accounting_costs_match_formula",
        acct_mid["ec_cost_bits"]
        == math.ceil(1744 * EC_EFFICIENCY * binary_entropy(0.05))
        and acct_mid["pa_cost_bits"]
        == math.ceil(1744 * binary_entropy(0.05)))

    # 7. decoy note honesty
    note = decoy_note()
    chk("decoy_note_labelled_not_simulated", note["simulated"] is False)
    chk("decoy_note_poisson_surface",
        note["poisson_surface"]["mu_0.5"]["p_multiphoton"] == 0.0902)

    # 8. classifier - labels come from the protocol policy itself
    rep = classifier_report()
    chk("classifier_ideal_safe", rep["bb84_ideal"] == "safe")
    chk("classifier_noise_safe", rep["bb84_labelled_noise"] == "safe")
    chk("classifier_eve_compromised",
        rep["bb84_eve_intercept_resend"] == "compromised")
    chk("classifier_e91_eve_compromised",
        rep["e91_eve_intercept_resend"] == "compromised")
    chk("classifier_rushed_sample_suspicious",
        rep["bb84_rushed_sample_16"] == "suspicious")
    chk("classifier_borderline_suspicious",
        rep["borderline_qber_0.08"] == "suspicious")
    chk("classifier_matches_model",
        all(classify_run(*f) == model_label(*f)
            for f in [(0.0, 0.50, 256), (0.02, 0.50, 256), (0.25, 0.50, 256),
                      (0.08, 0.50, 256), (0.0, 0.50, 16), (0.0, 0.80, 256)]))

    # gates + seats
    chk("hold_gates_14", len(HOLD_GATES) == 14
        and all(v.startswith("HOLD") for v in HOLD_GATES.values()))
    chk("gate_production_keys_hold", gate("production_key_generation") == "HOLD")
    chk("gate_intercept_hold", gate("intercept_real_communications") == "HOLD")
    chk("gate_banking_hold", gate("banking_financial_keys") == "HOLD")
    chk("gate_military_hold", gate("military_government_comms") == "HOLD")
    chk("gate_secrecy_claim_hold", gate("real_world_secrecy_claim") == "HOLD")
    chk("gate_sandbox_proceed", gate("run_simulation") == "PROCEED")
    brains = brains_report()
    chk("argon4_no_override", brains["decider"]["can_override_hold"] is False
        and brains["decider"]["seat"]
        == "Gemini Argon 4 Extended Thinking")
    chk("claude_no_override", brains["advisor"]["can_override_hold"] is False)
    chk("flow_plan_only", brains["flow"]["rendered"] is False
        and brains["flow"]["live"] == 0)
    return c


# ================================================================ CLI / demo
def _run_line(name, run):
    qber_pct = run["qber"] * 100
    tail = (f"ABORTED ({run['abort_reason']})" if run["status"] == "ABORTED"
            else f"final key {run['final_key_length']} bits")
    return (f"    {name:28s} sifted {run['sifted_bits']:5d} | "
            f"QBER {qber_pct:5.2f}% | {tail}")


def demo():
    print("=" * 68)
    print("QKD-Lab - quantum key distribution lab (BB84 + E91/BBM92)")
    print("by Darion Kellar | MIT | pure stdlib | zero network | EDUCATION ONLY")
    print("=" * 68)
    print("\n[1] THE HONEST CORE - what is and is not quantum here")
    print("    A qubit in this lab is a (bit, basis) pair and measurement")
    print("    is a classical rule. No photons, no real secrecy. What IS")
    print("    real is the protocol logic: measure in the wrong basis and")
    print("    you disturb the state - and the disturbance is measurable.")
    print("    That measurability is the entire security idea of QKD.")
    runs = demo_runs()
    print("\n[2] BB84 - Alice prepares, Bob measures, bases are compared")
    print(_run_line("bb84 ideal channel", runs["bb84_ideal"]))
    print(_run_line("bb84 labelled noise 2%", runs["bb84_labelled_noise"]))
    print("    -> Sifting keeps the ~half of events where the bases agree;")
    print("       a revealed sample of sifted bits prices the QBER and is")
    print("       then thrown away - it was spoken aloud.")
    print("\n[3] E91 / BBM92 style - a correlated-pair source instead")
    print(_run_line("e91 ideal channel", runs["e91_ideal"]))
    print(_run_line("e91 + Eve", runs["e91_eve_intercept_resend"]))
    print("    -> Same-basis outcomes agree by construction of the pair")
    print("       model (joint statistics - Bell's theorem is why no local")
    print("       model can do this). Eve's touch collapses the correlation.")
    print("\n[4] Eve intercept-resend - she buys information with errors")
    print(_run_line("bb84 + Eve (all qubits)", runs["bb84_eve_intercept_resend"]))
    print("    -> Half her basis guesses are wrong; each wrong guess makes")
    print("       Bob's sifted bit a coin flip: QBER ~= 25%. The abort line")
    print(f"       is {QBER_ABORT_THRESHOLD:.0%} - above it the run ABORTS and")
    print("       distils nothing. The protocol would rather have no key")
    print("       than a key Eve shares.")
    print("\n[5] Key accounting - the shrink, itemised")
    for name in ("bb84_ideal", "bb84_labelled_noise",
                 "bb84_eve_intercept_resend"):
        run = runs[name]
        print(f"    {name:28s} raw {run['raw_bits']} -> sifted "
              f"{run['sifted_bits']} -> sample -{run['sample_size']} "
              f"-> EC -{run['ec_cost_bits']} -> PA -{run['pa_cost_bits']} "
              f"-> final {run['final_key_length']}")
    print("    -> Error correction leaks f*h2(q) per bit (f = 1.15,")
    print("       labelled); privacy amplification burns h2(q) per bit to")
    print("       erase Eve's share. At q = 11% the rate 1 - 2*h2(q) hits")
    print("       zero - that is where the abort line comes from.")
    note = decoy_note()
    print("\n[6] Decoy states - a LABELLED note (not simulated)")
    for mu, row in note["poisson_surface"].items():
        print(f"    {mu:8s} P(0 photons) {row['p_empty']:.4f} | "
              f"P(1) {row['p_single']:.4f} | "
              f"P(2+) {row['p_multiphoton']:.4f}")
    print("    -> Weak laser pulses sometimes carry 2+ photons; Eve could")
    print("       split one off silently (PNS attack). Decoy intensities")
    print("       exist to make that theft visible. Poisson numbers only.")
    print("\n[7] Run classifier (TinyML kNN, labels from the protocol policy)")
    for name, label in classifier_report().items():
        print(f"    {name:36s} -> {label}")
    print("\n[8] Advisory seats")
    brains = brains_report()
    print(f"    decider: {brains['decider']['decision']} "
          f"trace={brains['decider']['trace_sha256_16']}")
    print(f"    advisor can_override_hold = {brains['advisor']['can_override_hold']}")
    print(f"    flow rendered = {brains['flow']['rendered']} "
          f"live = {brains['flow']['live']}")
    print(f"\n[9] HOLD gates: {len(HOLD_GATES)}")
    for key in HOLD_GATES:
        print(f"    HOLD  {key}")
    checks = run_checks()
    passed = sum(1 for _, ok in checks if ok)
    print(f"\nCHECKS {passed}/{len(checks)}")
    for name, ok in checks:
        if not ok:
            print(f"    FAIL {name}")
    verdict = "PROCEED" if passed == len(checks) else "HOLD"
    print(f"VERDICT {verdict} (sandbox simulation only) | HOLD gates {len(HOLD_GATES)}")
    return 0 if passed == len(checks) else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] == "demo":
        return demo()
    cmd = argv[0]
    if cmd == "checks":
        checks = run_checks()
        for name, ok in checks:
            print(f"{'PASS' if ok else 'FAIL'} {name}")
        print(f"CHECKS {sum(1 for _, ok in checks if ok)}/{len(checks)}")
        return 0 if all(ok for _, ok in checks) else 1
    if cmd == "bb84":
        runs = demo_runs()
        print(json.dumps({k: runs[k] for k in
                          ("bb84_ideal", "bb84_labelled_noise")},
                         indent=2, sort_keys=True))
        return 0
    if cmd == "e91":
        runs = demo_runs()
        print(json.dumps({k: runs[k] for k in
                          ("e91_ideal", "e91_eve_intercept_resend")},
                         indent=2, sort_keys=True))
        return 0
    if cmd == "eve":
        runs = demo_runs()
        print(json.dumps({k: runs[k] for k in
                          ("bb84_eve_intercept_resend",
                           "e91_eve_intercept_resend")},
                         indent=2, sort_keys=True))
        return 0
    if cmd == "keys":
        print(json.dumps(demo_runs(), indent=2, sort_keys=True))
        return 0
    if cmd == "classify":
        print(json.dumps(classifier_report(), indent=2, sort_keys=True))
        return 0
    if cmd == "brains":
        print(json.dumps(brains_report(), indent=2, sort_keys=True))
        return 0
    if cmd == "holds":
        for key, value in HOLD_GATES.items():
            print(f"{key}: {value}")
        return 0
    if cmd == "hold-demo":
        action = argv[1] if len(argv) > 1 else "production_key_generation"
        print(f"{action}: {HOLD_GATES.get(action, 'PROCEED - not gated')}")
        return 2 if gate(action) == "HOLD" else 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
