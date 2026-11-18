"""Tests for QKD-Lab: measurement model, BB84/E91 runs, Eve, keys, gates."""
import math

import pytest

import main as m


# ---- math helpers
def test_entropy_endpoints_and_half():
    assert m.binary_entropy(0.0) == 0.0
    assert m.binary_entropy(1.0) == 0.0
    assert m.binary_entropy(0.5) == 1.0


def test_entropy_at_abort_threshold():
    assert abs(m.binary_entropy(0.11) - 0.4999) < 0.001


def test_poisson_single_photon():
    assert abs(m.poisson_pmf(1.0, 1) - math.exp(-1)) < 1e-12


def test_multiphoton_mu_half():
    assert abs(m.multiphoton_probability(0.5) - 0.0902) < 0.001


def test_multiphoton_grows_with_mu():
    assert m.multiphoton_probability(0.1) < m.multiphoton_probability(0.5)
    assert m.multiphoton_probability(0.5) < m.multiphoton_probability(1.0)


# ---- measurement model
def test_measure_matching_basis_returns_bit():
    import random
    rng = random.Random(7)
    for basis in m.BASES:
        for bit in (0, 1):
            assert m.measure(bit, basis, basis, rng, 0.0) == bit


def test_measure_full_noise_always_flips():
    import random
    rng = random.Random(7)
    for bit in (0, 1):
        assert m.measure(bit, "+", "+", rng, 1.0) == 1 - bit


# ---- BB84 runs
def test_bb84_ideal_run():
    run = m.run_bb84()
    assert run["qber"] == 0.0
    assert run["sample_errors"] == 0
    assert run["status"] == "KEY_ESTABLISHED"
    assert run["abort_reason"] is None


def test_bb84_ideal_final_key_is_after_sample():
    run = m.run_bb84()
    assert run["ec_cost_bits"] == 0 and run["pa_cost_bits"] == 0
    assert run["final_key_length"] == run["after_sample"] == 1821


def test_bb84_sift_rate_near_half():
    run = m.run_bb84()
    assert 0.45 <= run["sift_rate"] <= 0.55
    assert run["sifted_bits"] == 2077


def test_bb84_noise_run():
    run = m.run_bb84(seed=m.SEED_BB84_NOISE, noise=m.LABELLED_NOISE)
    assert 0.0 < run["qber"] < m.SUSPICIOUS_QBER
    assert run["status"] == "KEY_ESTABLISHED"
    assert 0 < run["final_key_length"] < run["after_sample"]


def test_bb84_deterministic():
    assert m.run_bb84() == m.run_bb84()
    assert m.run_e91() == m.run_e91()


# ---- Eve intercept-resend
def test_eve_qber_above_20_percent():
    run = m.demo_runs()["bb84_eve_intercept_resend"]
    assert run["qber"] > 0.20
    assert abs(run["qber"] - 0.25) < 0.06


def test_eve_run_aborts_with_named_reason():
    run = m.demo_runs()["bb84_eve_intercept_resend"]
    assert run["status"] == "ABORTED"
    assert run["abort_reason"] == "QBER_ABOVE_ABORT_THRESHOLD"
    assert run["final_key_length"] == 0
    assert run["final_key_sha256_16"] is None


def test_partial_eve_between_noise_and_full():
    noisy = m.demo_runs()["bb84_labelled_noise"]
    full = m.demo_runs()["bb84_eve_intercept_resend"]
    partial = m.run_bb84(seed=m.SEED_BB84_EVE, noise=m.LABELLED_NOISE,
                         eve_fraction=0.5)
    assert noisy["qber"] < partial["qber"] < full["qber"]


# ---- E91 / BBM92 runs
def test_e91_ideal_run():
    run = m.run_e91()
    assert run["qber"] == 0.0
    assert run["status"] == "KEY_ESTABLISHED"
    assert run["final_key_length"] == 1805


def test_e91_eve_aborts():
    run = m.demo_runs()["e91_eve_intercept_resend"]
    assert run["qber"] > 0.20
    assert run["status"] == "ABORTED"
    assert run["abort_reason"] == "QBER_ABOVE_ABORT_THRESHOLD"
    assert run["final_key_length"] == 0


# ---- key accounting
def test_accounting_zero_qber_no_cost():
    acct = m.key_accounting(2000, 256, 0.0, aborted=False)
    assert acct["after_sample"] == 1744
    assert acct["final_key_length"] == 1744


def test_accounting_abort_zero_key():
    acct = m.key_accounting(2000, 256, 0.25, aborted=True)
    assert acct["final_key_length"] == 0
    assert acct["ec_cost_bits"] == 0 and acct["pa_cost_bits"] == 0


def test_accounting_costs_match_formula():
    acct = m.key_accounting(2000, 256, 0.05, aborted=False)
    assert acct["ec_cost_bits"] == math.ceil(
        1744 * m.EC_EFFICIENCY * m.binary_entropy(0.05))
    assert acct["pa_cost_bits"] == math.ceil(1744 * m.binary_entropy(0.05))


# ---- decoy note
def test_decoy_note_labelled_not_simulated():
    note = m.decoy_note()
    assert note["simulated"] is False
    assert note["poisson_surface"]["mu_0.5"]["p_multiphoton"] == 0.0902


# ---- classifier
def test_classifier_scenarios():
    rep = m.classifier_report()
    assert rep["bb84_ideal"] == "safe"
    assert rep["bb84_labelled_noise"] == "safe"
    assert rep["bb84_eve_intercept_resend"] == "compromised"
    assert rep["e91_eve_intercept_resend"] == "compromised"
    assert rep["bb84_rushed_sample_16"] == "suspicious"
    assert rep["borderline_qber_0.08"] == "suspicious"


def test_classifier_matches_model_on_scenarios():
    for features in [(0.0, 0.50, 256), (0.02, 0.50, 256), (0.25, 0.50, 256),
                     (0.08, 0.50, 256), (0.0, 0.50, 16), (0.0, 0.80, 256)]:
        assert m.classify_run(*features) == m.model_label(*features)


def test_model_label_thresholds():
    assert m.model_label(0.12, 0.50, 256) == "compromised"
    assert m.model_label(0.08, 0.50, 256) == "suspicious"
    assert m.model_label(0.0, 0.50, 32) == "suspicious"
    assert m.model_label(0.02, 0.50, 256) == "safe"


# ---- gates + seats
def test_hold_gates_count_and_style():
    assert len(m.HOLD_GATES) == 14
    assert all(v.startswith("HOLD") for v in m.HOLD_GATES.values())


@pytest.mark.parametrize("action", [
    "production_key_generation", "real_world_secrecy_claim",
    "intercept_real_communications", "banking_financial_keys",
    "military_government_comms",
])
def test_gated_actions_hold(action):
    assert m.gate(action) == "HOLD"


def test_sandbox_proceeds():
    assert m.gate("run_simulation") == "PROCEED"


def test_argon4_seat():
    decider = m.brains_report()["decider"]
    assert decider["seat"] == "Gemini Argon 4 Extended Thinking"
    assert decider["can_override_hold"] is False
    assert decider["live_calls"] == 0


def test_claude_and_flow_seats():
    brains = m.brains_report()
    assert brains["advisor"]["can_override_hold"] is False
    assert brains["flow"]["rendered"] is False
    assert brains["flow"]["live"] == 0


def test_hold_demo_exit_code(capsys):
    assert m.main(["hold-demo"]) == 2
    assert "production_key_generation" in capsys.readouterr().out


def test_checks_all_pass():
    checks = m.run_checks()
    assert all(ok for _, ok in checks)
    assert len(checks) == 45
