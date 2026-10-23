import pytest

from c2_exec_probe import decode_stats, classify, contract_errors, poll_done


def test_decode_stats_reads_every_key():
    text = ("armed=1 token=18818 budget_left=63 calls=2 skip=1 busy=0 "
            "js_calls=1 js_ok=1 js_err=0 mismatch=0 last_rc=1 "
            "last_token=18818 last_value=1504\n")
    d = decode_stats(text)
    assert d["token"] == 18818
    assert d["budget_left"] == 63
    assert d["js_ok"] == 1
    assert d["last_value"] == 1504


def test_decode_stats_accepts_negative_values():
    assert decode_stats("verified=-3 invalid=0\n") == {"verified": -3, "invalid": 0}


def test_decode_stats_rejects_duplicate_key():
    with pytest.raises(ValueError):
        decode_stats("js_ok=1 js_ok=2\n")


def test_decode_stats_rejects_non_integer_value():
    with pytest.raises(ValueError):
        decode_stats("js_ok=yes\n")


def test_classify_no_fire():
    assert classify({"fired": 0}, {"js_calls": 0}) == "no_fire"


def test_classify_ctx_skip_only():
    assert classify({"fired": 1, "ctx_skip": 3, "invalid": 0},
                    {"js_calls": 0}) == "ctx_skip_only"


def test_classify_fired_no_js():
    assert classify({"fired": 1, "ctx_skip": 0, "invalid": 1},
                    {"js_calls": 0}) == "fired_no_js"


def test_classify_ok_requires_one_ok_call_and_a_patch():
    assert classify({"fired": 1, "pred_patched": 1},
                    {"js_calls": 1, "js_ok": 1, "js_err": 0, "mismatch": 0}) == "ok"


def test_classify_error_on_js_error_or_mismatch():
    assert classify({"fired": 1, "pred_patched": 1},
                    {"js_calls": 1, "js_ok": 0, "js_err": 1, "mismatch": 0}) == "error"
    assert classify({"fired": 1, "pred_patched": 1},
                    {"js_calls": 1, "js_ok": 0, "js_err": 0, "mismatch": 1}) == "error"


def test_classify_ok_without_patch_is_error():
    assert classify({"fired": 1, "pred_patched": 0},
                    {"js_calls": 1, "js_ok": 1, "js_err": 0, "mismatch": 0}) == "error"


def test_contract_errors_accepts_a_complete_live_shot():
    live = {"token": 68637, "last_value": 1504}
    probe = {"chain": 0, "pred_patched": 1}
    assert contract_errors(live, probe, 68637) == []


def test_contract_errors_reads_the_pre_disarm_snapshot():
    # Disarm zeroes `token`; judging the post-cleanup read would reject a
    # shot that already proved the whole chain (2026-10-23 live run).
    live = {"token": 68637, "last_value": 1504}
    post = {"token": 0, "last_value": 0}
    probe = {"chain": 0, "pred_patched": 1}
    assert contract_errors(live, probe, 68637) == []
    assert any("token" in e for e in contract_errors(post, probe, 68637))


def test_contract_errors_flags_every_broken_term():
    probe = {"chain": 0, "pred_patched": 1}
    assert any("1504" in e for e in
               contract_errors({"token": 68637, "last_value": 0}, probe, 68637))
    assert any("chain" in e for e in
               contract_errors({"token": 68637, "last_value": 1504},
                               {"chain": 1, "pred_patched": 1}, 68637))
    assert any("patch" in e for e in
               contract_errors({"token": 68637, "last_value": 1504},
                               {"chain": 0, "pred_patched": 0}, 68637))


def test_poll_done_waits_for_the_js_leg_after_a_fired_read():
    # fireOnce() flips `fired` before instantiate() runs, so a stats read can
    # catch the shot mid-chain with js_calls still 0.
    assert not poll_done({"fired": 1}, {"js_calls": 0})
    assert poll_done({"fired": 1}, {"js_calls": 1})
    assert poll_done({"fired": 1}, {"js_calls": 1, "js_err": 1})
    assert not poll_done({"fired": 0}, {"js_calls": 0})
