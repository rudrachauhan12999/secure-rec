"""GUI tests: backend adapter, presenter, safety rules and the real Tk window
(hidden; no pixel/screenshot assertions)."""

from __future__ import annotations

import ast
import gc
import hashlib
import threading
import time
from pathlib import Path

import pytest

from app.gui import file_opener, presenter, task_registry
from app.gui.worker import BackgroundWorker
from core import certificates as certs
from core.config import PROJECT_ROOT
from core.results import Status, TaskResult
from core.validators import InputValidationError
from tasks import task03_ecb_cbc

# A Tk object collected on a worker thread corrupts the Tcl interpreter; treat it as a failure.
pytestmark = pytest.mark.filterwarnings("error::pytest.PytestUnraisableExceptionWarning")

GUI_DIR = PROJECT_ROOT / "app"
FORBIDDEN_IMPORTS = {"Crypto", "cryptography", "hashlib", "hmac", "secrets", "ssl", "random",
                     "core.crypto_utils", "core.hybrid", "core.signatures", "core.diffie_hellman",
                     "core.key_manager", "core.certificates", "pipeline.sender", "pipeline.package"}


def _openssl_available() -> bool:
    try:
        certs.find_openssl()
        return True
    except certs.OpenSSLNotFound:
        return False


needs_openssl = pytest.mark.skipif(not _openssl_available(), reason="OpenSSL not installed")


# ----------------------------------------------------------------- structure
def test_gui_modules_import():
    import app.gui.app  # noqa: F401
    import app.gui.components.file_panel  # noqa: F401
    import app.gui.components.result_panel  # noqa: F401
    import app.gui.components.status_bar  # noqa: F401
    import app.gui.dashboard  # noqa: F401
    import app.main  # noqa: F401


def test_no_cryptography_in_gui_code():
    for path in GUI_DIR.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for name in names:
                assert not any(name == f or name.startswith(f + ".") for f in FORBIDDEN_IMPORTS), \
                    f"{path.name} imports {name}"
        text = path.read_text(encoding="utf-8")
        for token in ("AES.new", "PKCS1_OAEP", "pss.new", "pow(", "sha256(", "get_random_bytes"):
            assert token not in text, f"{path.name} contains {token}"


def test_registry_calls_existing_task_functions():
    import importlib

    assert [s.key for s in task_registry.TASKS] == [f"task{i:02d}" for i in range(1, 13)]
    for spec in task_registry.TASKS:
        module = importlib.import_module(spec.func.__module__)
        assert module.__name__.startswith("tasks.") and module.TASK_ID == spec.key
        assert spec.func is module.run and spec.title == module.TITLE
    assert task_registry.TASK_BY_KEY["task03"].input_kind == task_registry.IMAGE
    assert task_registry.TASK_BY_KEY["task04"].input_kind == task_registry.BENCHMARK
    assert {task_registry.TASK_BY_KEY[k].input_kind for k in ("task06", "task12")} == {task_registry.NONE}


# ------------------------------------------------------------- file handling
def test_inspect_valid_file(sample_file, binary_file, png_image):
    summary = task_registry.inspect_file(sample_file)
    assert summary.name == "student_records.txt" and summary.type_label == "TXT"
    assert summary.sha256 == hashlib.sha256(sample_file.read_bytes()).hexdigest()
    assert not summary.is_image and task_registry.inspect_file(png_image).is_image
    assert task_registry.inspect_file(binary_file).size_bytes == binary_file.stat().st_size


def test_inspect_invalid_file(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    for bad in (tmp_path / "missing.txt", empty, tmp_path):
        with pytest.raises(InputValidationError):
            task_registry.inspect_file(bad)


def test_no_file_selected_gives_clean_error(out_root):
    result = task_registry.run_task("task01", None, output_root=out_root)
    assert result.status is Status.ERROR and "No file selected" in result.reason
    assert task_registry.run_pipeline(None, output_root=out_root).status is Status.ERROR


def test_task3_non_image_is_not_applicable(sample_file, out_root):
    result = task_registry.run_task("task03", sample_file, output_root=out_root)
    model = presenter.present(result)
    assert model.status == "NOT APPLICABLE" and model.kind == "na"
    assert model.reason == "Image input required"


def test_tasks_without_file_still_run(out_root):
    assert task_registry.run_task("task06", None, output_root=out_root).status is Status.PASS
    assert task_registry.run_task("task12", None, output_root=out_root).status is Status.PASS


# ------------------------------------------------------------------ presenter
def test_present_generic_result(tmp_path):
    report = tmp_path / "task99" / "report.txt"
    report.parent.mkdir()
    report.write_text("r")
    private = tmp_path / "task99" / "sender_private_key.pem"
    private.write_text("-----BEGIN PRIVATE KEY-----")
    result = TaskResult("task99", "Demo", status=Status.PASS, artifacts=[report, private, tmp_path / "gone.bin"])
    result.add("Long", "x" * 1000)
    result.add("Leak", "-----BEGIN PRIVATE KEY----- abc")
    model = presenter.present(result)
    assert model.kind == "pass" and model.report == report and model.output_dir == report.parent
    assert model.artifacts == [report]                               # private + missing filtered out
    assert len(dict(model.summary)["Long"]) <= presenter.MAX_VALUE_CHARS
    assert dict(model.summary)["Leak"] == "[hidden]"


def test_present_task3_image_actions(png_image, out_root):
    model = presenter.present(task_registry.run_task("task03", png_image, output_root=out_root))
    labels = [a.label for a in model.actions]
    assert {"Open Comparison Image", "Open ECB Image", "Open CBC Image"} <= set(labels)
    assert model.thumbnail and model.thumbnail.name == "comparison_original_ecb_cbc.png"


def test_present_task4_table_and_chart(tmp_path, out_root):
    result = task_registry.run_task("task04", None, output_root=out_root, bench_dir=tmp_path / "b", repeats=3)
    model = presenter.present(result)
    assert "AES-128-CBC" in model.extra_text and "100 KB" in model.extra_text
    assert "Open Chart" in [a.label for a in model.actions]


@needs_openssl
def test_present_task11_and_task12(sample_file, out_root, tmp_path, rsa_key):
    m11 = presenter.present(task_registry.run_task("task11", sample_file, out_root, tmp_path / "keys",
                                                   sender_key=rsa_key))
    assert "Open Certificate Information" in [a.label for a in m11.actions]
    assert not any("private" in p.name for p in m11.artifacts)
    m12 = presenter.present(task_registry.run_task("task12", None, out_root, password="Viva-Secret-99"))
    assert "Viva-Secret-99" not in m12.extra_text and "(1) Client -> AS" in m12.extra_text


@needs_openssl
def test_present_pipeline_normal_and_tamper(binary_file, out_root, tmp_path, rsa_identities):
    keys = dict(sender_key=rsa_identities["sender"], receiver_key=rsa_identities["receiver"])
    ok = presenter.present(task_registry.run_pipeline(binary_file, False, out_root, tmp_path / "k", **keys))
    assert ok.final == "SECURE TRANSFER SUCCESSFUL" and ok.status == "PASS"
    assert presenter.FAILED not in ok.extra_text and "File recovery" in ok.extra_text

    bad = presenter.present(task_registry.run_pipeline(binary_file, True, out_root, tmp_path / "k", **keys))
    assert bad.final == "SECURE TRANSFER REJECTED"
    assert bad.reason.startswith("Digital signature verification failed")
    assert f"{presenter.FAILED} Digital signature verification" in bad.extra_text
    assert f"{presenter.NOT_RUN} AES decryption" in bad.extra_text
    assert "tampering detected" in bad.status


# ------------------------------------------------------------- safe opening
def test_open_path_restricted_to_output_roots(tmp_path):
    inside = tmp_path / "outputs" / "task01" / "report.txt"
    inside.parent.mkdir(parents=True)
    inside.write_text("x")
    opened = []
    file_opener.open_path(inside, [tmp_path / "outputs"], opened.append)
    assert opened == [inside.resolve()]
    for bad in (tmp_path / "keys" / "k.pem", tmp_path / "outputs" / ".." / "secret.txt", Path("C:/Windows")):
        with pytest.raises(file_opener.UnsafePathError):
            file_opener.open_path(bad, [tmp_path / "outputs"], opened.append)
    with pytest.raises(FileNotFoundError):
        file_opener.open_path(tmp_path / "outputs" / "nope.txt", [tmp_path / "outputs"], opened.append)


# -------------------------------------------------------------------- worker
def test_worker_success_error_and_busy():
    pending = []
    worker = BackgroundWorker(lambda ms, fn: pending.append(fn))
    results, errors = [], []
    gate = threading.Event()
    assert worker.submit(lambda: gate.wait(5) and 42, results.append, errors.append)
    assert not worker.submit(lambda: 1, results.append, errors.append)      # refused while busy
    gate.set()
    deadline = time.time() + 5
    while not results and time.time() < deadline:
        pending.pop(0)()
    assert results == [42] and not worker.busy

    worker.submit(lambda: 1 / 0, results.append, errors.append)
    while not errors and time.time() < deadline + 5:
        pending.pop(0)()
    assert isinstance(errors[0], ZeroDivisionError)


# ------------------------------------------------------------ real Tk window
@pytest.fixture
def gui(tmp_path):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no display available ({exc})")
    root.withdraw()
    from app.gui.app import SecureRecApp

    opened: list[Path] = []
    app = SecureRecApp(root, output_root=tmp_path / "outputs", keys_root=tmp_path / "keys", launcher=opened.append,
                       load_sample=False, show_dialogs=False, ask_open_file=lambda **kw: "")
    app.opened = opened

    def pump(timeout: float = 120) -> None:
        deadline = time.time() + timeout
        root.update()
        while app.busy:
            if time.time() > deadline:
                raise TimeoutError("GUI job did not finish")
            root.update()
            time.sleep(0.01)
        root.update()

    app.pump = pump
    yield app
    root.destroy()
    del app, root
    # Collect this window's reference cycles now, on the main thread. Otherwise the cyclic
    # GC may free them later on a worker thread of another test, which corrupts Tcl.
    gc.collect()


def test_gui_select_valid_and_invalid_file(gui, sample_file, tmp_path):
    gui.select_path(sample_file)
    gui.pump()
    assert gui.selected.name == "student_records.txt"
    assert gui.file_panel.vars["SHA-256"].get() == hashlib.sha256(sample_file.read_bytes()).hexdigest()

    gui.select_path(tmp_path / "does-not-exist.pdf")
    gui.pump()
    assert gui.selected is None and "not found" in gui.file_panel.message.cget("text").lower()

    gui.run_task("task01")
    gui.pump()
    assert gui.result_panel.model.status == "ERROR" and "No file selected" in gui.result_panel.model.reason


def test_gui_displays_task_result_and_task3_rule(gui, sample_file):
    gui.select_path(sample_file)
    gui.pump()
    gui.run_task("task03")
    gui.pump()
    assert gui.result_panel.status_label.cget("text") == "NOT APPLICABLE"
    assert "Image input required" in gui.result_panel.reason_label.cget("text")

    gui.run_task("task01")
    gui.pump()
    assert gui.result_panel.status_label.cget("text") == "PASS"
    assert "AES-128-CBC bytes identical" in gui.result_panel.visible_text()
    assert "Open Report" in gui.result_panel.action_labels()


def test_gui_buttons_disabled_while_running(gui):
    gate = threading.Event()
    gui._start("waiting", lambda: gate.wait(5), lambda v: None, lambda e: None)
    assert str(gui.dashboard.pipeline_button.cget("state")) == "disabled"
    assert all(str(b.cget("state")) == "disabled" for b in gui.dashboard.task_buttons.values())
    gate.set()
    gui.pump()
    assert str(gui.dashboard.pipeline_button.cget("state")) == "normal"


def test_gui_open_actions_are_confined(gui, sample_file):
    gui.select_path(sample_file)
    gui.pump()
    gui.run_task("task08")
    gui.pump()
    gui.open_path(gui.result_panel.model.report)
    assert gui.opened and gui.opened[-1].name == "report.txt"
    gui.open_path(PROJECT_ROOT / "README.md")                  # outside outputs -> refused, not opened
    assert gui.opened[-1].name == "report.txt" and "Cannot open" in gui.status_bar.text


@needs_openssl
def test_gui_pipeline_and_tamper_show_no_secrets(gui, binary_file, monkeypatch, tmp_path):
    session_key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    monkeypatch.setattr("core.hybrid.generate_aes_key", lambda bits=128: session_key)
    gui.select_path(binary_file)
    gui.pump()
    gui.run_pipeline(False)
    gui.pump()
    assert gui.result_panel.final_label.cget("text") == "SECURE TRANSFER SUCCESSFUL"
    shown = gui.result_panel.visible_text()
    gui.run_pipeline(True)
    gui.pump()
    assert gui.result_panel.final_label.cget("text") == "SECURE TRANSFER REJECTED"
    assert "Digital signature" in gui.result_panel.reason_label.cget("text")
    shown += gui.result_panel.visible_text()

    for secret in ("PRIVATE KEY", session_key.hex()):
        assert secret not in shown
    for f in (tmp_path / "outputs").rglob("*"):
        if f.is_file():
            content = f.read_bytes()
            assert b"PRIVATE KEY" not in content and session_key not in content, f
    assert (tmp_path / "keys" / "integrated_pipeline" / "receiver_private_key.pem").exists()


def test_gui_image_task3_passes(gui, tmp_path):
    image = task03_ecb_cbc.generate_demo_image(tmp_path / "pic.png")
    gui.select_path(image)
    gui.pump()
    gui.run_task("task03")
    gui.pump()
    assert gui.result_panel.status_label.cget("text") == "PASS"
    assert "Open Comparison Image" in gui.result_panel.action_labels()
