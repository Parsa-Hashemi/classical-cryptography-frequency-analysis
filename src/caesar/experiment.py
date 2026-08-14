"""Cryptanalysis success-rate and runtime experiments.

Outputs use CSV so results remain reproducible without pandas. When
matplotlib is installed, three primary charts are also created in
``docs/images``.
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
import time
from pathlib import Path
from typing import Callable, Iterable

try:  # Support both package execution and direct script execution.
    from .analysis import (
        chi_square_scores,
        clean_letters,
        compare_statistics,
        crack_by_ngram,
        crack_caesar,
        frequency_rows,
        ngram_counts,
    )
    from .caesar import brute_force, decrypt, encrypt
except ImportError:  # pragma: no cover - used by python src/experiment.py.
    from analysis import (
        chi_square_scores,
        clean_letters,
        compare_statistics,
        crack_by_ngram,
        crack_caesar,
        frequency_rows,
        ngram_counts,
    )
    from caesar import brute_force, decrypt, encrypt


DEFAULT_LENGTHS = (10, 20, 50, 100, 200, 500, 1000)
DEFAULT_TRIALS = 100
DEFAULT_TEXT_PATH = Path(__file__).resolve().parents[1] / "data" / "input" / "english_sample.txt"


DEFAULT_CORPUS = """
Mathematics gives us a precise language for describing patterns, operations,
and transformations. A small experiment can connect an abstract formula to
an observable result. In a classical cipher, each letter is represented by a
number and a key moves that number around a circular alphabet. The Caesar
cipher is simple enough to explain completely, yet it shows important ideas
about modular arithmetic, inverse functions, search spaces, and statistical
evidence.

When a message is long enough, the distribution of letters contains clues
about the language of the original text. A shift changes the labels of the
letters, but it does not change how many symbols occur. This makes the cipher
useful for a classroom experiment: brute force can test every possible key,
chi square can compare a candidate with English frequencies, and n grams can
provide another view of the same decision. The experiment should record both
correct decisions and running time so that conclusions are based on data.

Clear documentation is part of a good scientific program. We state the
formula, implement it directly, test edge cases, keep random experiments
reproducible with a seed, and save results in ordinary CSV files. The goal is
not to make a complex system. The goal is to understand why a key space of
only twenty six possibilities is not sufficient for security, and to measure
how text length affects a statistical guess.
"""


def load_corpus(path: str | Path | None = None) -> str:
    """Read the experiment corpus from a UTF-8 file."""

    corpus_path = Path(path) if path is not None else DEFAULT_TEXT_PATH
    if corpus_path.exists():
        text = corpus_path.read_text(encoding="utf-8")
        if clean_letters(text):
            return text
    return DEFAULT_CORPUS


def _letter_corpus(corpus: str, minimum_length: int) -> str:
    letters = clean_letters(corpus)
    if not letters:
        raise ValueError("the input text must contain at least one English letter")
    if len(letters) < minimum_length:
        repetitions = minimum_length // len(letters) + 1
        letters = letters * repetitions
    return letters


def _random_fragment(letters: str, length: int, rng: random.Random) -> str:
    if length <= 0:
        raise ValueError("text length must be positive")
    if len(letters) < length:
        raise ValueError("the input text is too short for the experiment length")
    start = rng.randrange(0, len(letters) - length + 1)
    return letters[start : start + length]


def _crack(ciphertext: str, method: str) -> dict[str, int | float | str]:
    if method == "chi-square":
        return crack_caesar(ciphertext)
    if method == "ngram":
        return crack_by_ngram(ciphertext)
    raise ValueError("method must be chi-square or ngram")


def run_success_rate(
    lengths: Iterable[int] = DEFAULT_LENGTHS,
    trials: int = DEFAULT_TRIALS,
    seed: int = 42,
    corpus: str | None = None,
    method: str = "chi-square",
) -> list[dict[str, int | float | str]]:
    """Measure key-recovery success rates for different text lengths."""

    lengths = tuple(int(length) for length in lengths)
    if not lengths or any(length <= 0 for length in lengths):
        raise ValueError("lengths must contain positive numbers")
    if trials <= 0:
        raise ValueError("trials must be positive")

    letters = _letter_corpus(corpus or load_corpus(), max(lengths))
    rng = random.Random(seed)
    rows: list[dict[str, int | float | str]] = []

    for length in lengths:
        correct = 0
        for _ in range(trials):
            plaintext = _random_fragment(letters, length, rng)
            actual_key = rng.randrange(26)
            ciphertext = encrypt(plaintext, actual_key)
            predicted_key = int(_crack(ciphertext, method)["key"])
            correct += int(predicted_key == actual_key)
        rows.append(
            {
                "method": method,
                "length": length,
                "trials": trials,
                "correct": correct,
                "success_rate": correct / trials,
            }
        )
    return rows


def _average_milliseconds(function: Callable[[], object], repeats: int) -> float:
    start = time.perf_counter()
    for _ in range(repeats):
        function()
    elapsed = time.perf_counter() - start
    return elapsed * 1000 / repeats


def run_runtime_benchmark(
    lengths: Iterable[int] = DEFAULT_LENGTHS,
    repeats: int = 5,
    seed: int = 42,
    corpus: str | None = None,
) -> list[dict[str, int | float]]:
    """Record average runtimes for core operations in milliseconds."""

    lengths = tuple(int(length) for length in lengths)
    if not lengths or any(length <= 0 for length in lengths):
        raise ValueError("lengths must contain positive numbers")
    if repeats <= 0:
        raise ValueError("repeats must be positive")

    letters = _letter_corpus(corpus or load_corpus(), max(lengths))
    rng = random.Random(seed)
    rows: list[dict[str, int | float]] = []

    for length in lengths:
        plaintext = _random_fragment(letters, length, rng)
        key = rng.randrange(26)
        ciphertext = encrypt(plaintext, key)
        rows.append(
            {
                "length": length,
                "repeats": repeats,
                "encrypt_ms": _average_milliseconds(lambda: encrypt(plaintext, key), repeats),
                "decrypt_ms": _average_milliseconds(lambda: decrypt(ciphertext, key), repeats),
                "brute_force_ms": _average_milliseconds(lambda: brute_force(ciphertext), repeats),
                "statistical_crack_ms": _average_milliseconds(
                    lambda: crack_caesar(ciphertext), repeats
                ),
            }
        )
    return rows


def _write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _statistics_rows(corpus: str, key: int = 5) -> list[dict[str, object]]:
    plaintext = corpus
    ciphertext = encrypt(plaintext, key)
    statistics = compare_statistics(plaintext, ciphertext)
    return [
        {
            "text": "plaintext",
            "key": "",
            "index_of_coincidence": statistics["plaintext_ic"],
            "shannon_entropy": statistics["plaintext_entropy"],
        },
        {
            "text": "ciphertext",
            "key": key,
            "index_of_coincidence": statistics["ciphertext_ic"],
            "shannon_entropy": statistics["ciphertext_entropy"],
        },
    ]


def _save_frequency_csv(corpus: str, path: Path) -> None:
    rows = [
        {
            "letter": row["letter"],
            "count": row["count"],
            "frequency": row["frequency"],
            "percentage": row["percentage"],
        }
        for row in frequency_rows(corpus)
    ]
    _write_csv(path, rows, ["letter", "count", "frequency", "percentage"])


def _save_ngram_csv(corpus: str, n: int, path: Path) -> None:
    counts = ngram_counts(corpus, n)
    total = sum(counts.values())
    rows = [
        {
            "ngram": gram,
            "count": count,
            "frequency": count / total if total else 0.0,
            "percentage": (count / total * 100) if total else 0.0,
        }
        for gram, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    _write_csv(path, rows, ["ngram", "count", "frequency", "percentage"])


def _save_cracking_csv(corpus: str, path: Path, key: int = 5) -> None:
    ciphertext = encrypt(corpus, key)
    best = crack_caesar(ciphertext)
    rows = [
        {
            "key": row["key"],
            "chi_square": row["score"],
            "is_selected": int(int(row["key"]) == int(best["key"])),
            "plaintext": row["plaintext"],
        }
        for row in chi_square_scores(ciphertext)
    ]
    _write_csv(path, rows, ["key", "chi_square", "is_selected", "plaintext"])


def _save_entropy_csv(statistics: list[dict[str, object]], path: Path) -> None:
    rows = [
        {
            "text": row["text"],
            "key": row["key"],
            "entropy_bits": row["shannon_entropy"],
        }
        for row in statistics
    ]
    _write_csv(path, rows, ["text", "key", "entropy_bits"])


def _create_frequency_plot(frequency_path: Path, image_path: Path) -> Path | None:
    """Create a letter-frequency chart from a generated frequency CSV file."""

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    with frequency_path.open(encoding="utf-8-sig", newline="") as file:
        frequency_data = list(csv.DictReader(file))

    image_path.parent.mkdir(parents=True, exist_ok=True)
    figure, axis = plt.subplots(figsize=(10, 5))
    axis.bar(
        [row["letter"] for row in frequency_data],
        [float(row["percentage"]) for row in frequency_data],
        color="#4472C4",
    )
    axis.set_title("Input Text Letter Frequencies")
    axis.set_xlabel("Letter")
    axis.set_ylabel("Frequency (percent)")
    axis.grid(axis="y", alpha=0.3)
    figure.tight_layout()
    figure.savefig(image_path, dpi=150)
    plt.close(figure)
    return image_path


def save_frequency_artifacts(
    text: str, project_root: str | Path | None = None
) -> dict[str, Path]:
    """Update the standard frequency CSV and chart for the supplied text."""

    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[1]
    csv_path = root / "data" / "output" / "letter_frequency.csv"
    image_path = root / "docs" / "images" / "letter_frequency.png"
    _save_frequency_csv(text, csv_path)
    generated_image = _create_frequency_plot(csv_path, image_path)
    outputs = {"frequency": csv_path}
    if generated_image is not None:
        outputs["chart"] = generated_image
    return outputs


def save_ngram_artifacts(
    text: str, project_root: str | Path | None = None
) -> dict[str, Path]:
    """Update the standard bigram and trigram CSV files for supplied text."""

    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[1]
    output_dir = root / "data" / "output"
    bigram_path = output_dir / "bigram_frequency.csv"
    trigram_path = output_dir / "trigram_frequency.csv"
    _save_ngram_csv(text, 2, bigram_path)
    _save_ngram_csv(text, 3, trigram_path)
    return {"bigram": bigram_path, "trigram": trigram_path}


def save_statistics_artifacts(
    text: str, project_root: str | Path | None = None
) -> dict[str, Path]:
    """Update standard statistics and entropy CSV files for supplied text."""

    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[1]
    output_dir = root / "data" / "output"
    statistics_path = output_dir / "statistics.csv"
    entropy_path = output_dir / "entropy_results.csv"
    statistics = _statistics_rows(text)
    _write_csv(
        statistics_path,
        statistics,
        ["text", "key", "index_of_coincidence", "shannon_entropy"],
    )
    _save_entropy_csv(statistics, entropy_path)
    return {"statistics": statistics_path, "entropy": entropy_path}


def _create_experiment_plots(
    success_rows: list[dict[str, object]],
    runtime_rows: list[dict[str, object]],
    image_dir: Path,
) -> list[Path]:
    """Create success-rate and runtime charts when matplotlib is available."""

    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib import font_manager
    except ImportError:
        return []

    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
    except ImportError:
        # CSV output does not depend on these packages, and charts can still
        # be generated when they are unavailable.
        def shape_rtl(value: str) -> str:
            return value
    else:
        def shape_rtl(value: str) -> str:
            return get_display(arabic_reshaper.reshape(value))

    font_path = font_manager.findfont("Tahoma", fallback_to_default=True)
    font_properties = font_manager.FontProperties(fname=font_path)
    plt.rcParams["axes.unicode_minus"] = False

    image_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    methods = sorted({str(row["method"]) for row in success_rows})
    figure, axis = plt.subplots(figsize=(8, 5))
    for method in methods:
        rows = [row for row in success_rows if str(row["method"]) == method]
        axis.plot(
            [int(row["length"]) for row in rows],
            [float(row["success_rate"]) * 100 for row in rows],
            marker="o",
            label=method,
        )
    axis.set_title(shape_rtl("Cryptanalysis Success Rate by Text Length"), fontproperties=font_properties)
    axis.set_xlabel(shape_rtl("Text Length (letters)"), fontproperties=font_properties)
    axis.set_ylabel(shape_rtl("Success Rate (percent)"), fontproperties=font_properties)
    axis.set_ylim(0, 105)
    axis.grid(alpha=0.3)
    axis.legend(prop=font_properties)
    figure.tight_layout()
    success_path = image_dir / "success_rate.png"
    figure.savefig(success_path, dpi=150)
    plt.close(figure)
    generated.append(success_path)

    figure, axis = plt.subplots(figsize=(8, 5))
    axis.plot(
        [int(row["length"]) for row in runtime_rows],
        [float(row["brute_force_ms"]) for row in runtime_rows],
        marker="o",
        label="brute force",
    )
    axis.plot(
        [int(row["length"]) for row in runtime_rows],
        [float(row["statistical_crack_ms"]) for row in runtime_rows],
        marker="s",
        label="chi-square",
    )
    axis.set_title(shape_rtl("Cryptanalysis Runtime"), fontproperties=font_properties)
    axis.set_xlabel(shape_rtl("Text Length (letters)"), fontproperties=font_properties)
    axis.set_ylabel(shape_rtl("Average Runtime (milliseconds)"), fontproperties=font_properties)
    axis.grid(alpha=0.3)
    axis.legend(prop=font_properties)
    figure.tight_layout()
    runtime_path = image_dir / "runtime.png"
    figure.savefig(runtime_path, dpi=150)
    plt.close(figure)
    generated.append(runtime_path)

    return generated


def run_performance_experiments(
    lengths: Iterable[int] = DEFAULT_LENGTHS,
    trials: int = DEFAULT_TRIALS,
    runtime_repeats: int = 5,
    seed: int = 42,
    corpus_path: str | Path | None = None,
    compare_methods: bool = False,
    project_root: str | Path | None = None,
    corpus_text: str | None = None,
) -> dict[str, object]:
    """Generate only success-rate and runtime experiment artifacts."""

    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[1]
    corpus = corpus_text if corpus_text is not None else load_corpus(corpus_path)
    lengths = tuple(int(length) for length in lengths)
    methods = ["chi-square", "ngram"] if compare_methods else ["chi-square"]

    success_rows: list[dict[str, int | float | str]] = []
    for index, method in enumerate(methods):
        success_rows.extend(
            run_success_rate(
                lengths=lengths,
                trials=trials,
                seed=seed + index,
                corpus=corpus,
                method=method,
            )
        )
    runtime_rows = run_runtime_benchmark(
        lengths=lengths,
        repeats=runtime_repeats,
        seed=seed,
        corpus=corpus,
    )

    output_dir = root / "data" / "output"
    benchmark_dir = root / "benchmarks"
    image_dir = root / "docs" / "images"
    input_path = output_dir / "experiment_input.txt"
    success_path = output_dir / "success_rate.csv"
    runtime_path = output_dir / "runtime.csv"
    benchmark_path = benchmark_dir / "results.csv"

    output_dir.mkdir(parents=True, exist_ok=True)
    input_path.write_text(corpus, encoding="utf-8")
    _write_csv(
        success_path,
        [dict(row) for row in success_rows],
        ["method", "length", "trials", "correct", "success_rate"],
    )
    runtime_fields = [
        "length",
        "repeats",
        "encrypt_ms",
        "decrypt_ms",
        "brute_force_ms",
        "statistical_crack_ms",
    ]
    _write_csv(runtime_path, [dict(row) for row in runtime_rows], runtime_fields)
    _write_csv(benchmark_path, [dict(row) for row in runtime_rows], runtime_fields)
    generated_images = _create_experiment_plots(
        success_rows, runtime_rows, image_dir
    )
    return {
        "input": input_path,
        "success_rate": success_path,
        "runtime": runtime_path,
        "benchmark": benchmark_path,
        "images": generated_images,
    }


def run_all_experiments(
    lengths: Iterable[int] = DEFAULT_LENGTHS,
    trials: int = DEFAULT_TRIALS,
    runtime_repeats: int = 5,
    seed: int = 42,
    corpus_path: str | Path | None = None,
    compare_methods: bool = False,
    project_root: str | Path | None = None,
    corpus_text: str | None = None,
) -> dict[str, object]:
    """Generate all project CSV files and charts from the selected input text.

    ``corpus_text`` takes precedence when text is entered directly. Otherwise,
    ``corpus_path`` is read, or the bundled sample is used when neither source
    is supplied.
    """

    root = Path(project_root) if project_root is not None else Path(__file__).resolve().parents[1]
    corpus = corpus_text if corpus_text is not None else load_corpus(corpus_path)
    lengths = tuple(int(length) for length in lengths)

    methods = ["chi-square", "ngram"] if compare_methods else ["chi-square"]
    success_rows: list[dict[str, int | float | str]] = []
    for index, method in enumerate(methods):
        success_rows.extend(
            run_success_rate(
                lengths=lengths,
                trials=trials,
                seed=seed + index,
                corpus=corpus,
                method=method,
            )
        )
    runtime_rows = run_runtime_benchmark(
        lengths=lengths,
        repeats=runtime_repeats,
        seed=seed,
        corpus=corpus,
    )

    output_dir = root / "data" / "output"
    benchmark_dir = root / "benchmarks"
    image_dir = root / "docs" / "images"
    success_path = output_dir / "success_rate.csv"
    runtime_path = output_dir / "runtime.csv"
    frequency_path = output_dir / "letter_frequency.csv"
    bigram_path = output_dir / "bigram_frequency.csv"
    trigram_path = output_dir / "trigram_frequency.csv"
    statistics_path = output_dir / "statistics.csv"
    entropy_path = output_dir / "entropy_results.csv"
    cracking_path = output_dir / "cracking_results.csv"
    input_path = output_dir / "analysis_input.txt"
    benchmark_path = benchmark_dir / "results.csv"

    output_dir.mkdir(parents=True, exist_ok=True)
    input_path.write_text(corpus, encoding="utf-8")

    _write_csv(
        success_path,
        [dict(row) for row in success_rows],
        ["method", "length", "trials", "correct", "success_rate"],
    )
    _write_csv(
        runtime_path,
        [dict(row) for row in runtime_rows],
        [
            "length",
            "repeats",
            "encrypt_ms",
            "decrypt_ms",
            "brute_force_ms",
            "statistical_crack_ms",
        ],
    )
    _write_csv(
        benchmark_path,
        [dict(row) for row in runtime_rows],
        [
            "length",
            "repeats",
            "encrypt_ms",
            "decrypt_ms",
            "brute_force_ms",
            "statistical_crack_ms",
        ],
    )
    _save_frequency_csv(corpus, frequency_path)
    _save_ngram_csv(corpus, 2, bigram_path)
    _save_ngram_csv(corpus, 3, trigram_path)
    statistics = _statistics_rows(corpus)
    _write_csv(statistics_path, statistics, ["text", "key", "index_of_coincidence", "shannon_entropy"])
    _save_entropy_csv(statistics, entropy_path)
    _save_cracking_csv(corpus, cracking_path)
    generated_images = _create_experiment_plots(success_rows, runtime_rows, image_dir)
    frequency_image = _create_frequency_plot(
        frequency_path, image_dir / "letter_frequency.png"
    )
    if frequency_image is not None:
        generated_images.append(frequency_image)

    return {
        "input": input_path,
        "success_rate": success_path,
        "runtime": runtime_path,
        "statistics": statistics_path,
        "entropy": entropy_path,
        "frequency": frequency_path,
        "bigram": bigram_path,
        "trigram": trigram_path,
        "cracking": cracking_path,
        "benchmark": benchmark_path,
        "images": generated_images,
    }


def _parse_lengths(value: str) -> tuple[int, ...]:
    try:
        lengths = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "lengths must be comma-separated integers"
        ) from error
    if not lengths or any(length <= 0 for length in lengths):
        raise argparse.ArgumentTypeError("lengths must be positive")
    return lengths


def main() -> None:
    # Windows consoles may otherwise default to cp1252.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Run Caesar cipher experiments")
    parser.add_argument(
        "--lengths",
        type=_parse_lengths,
        default=DEFAULT_LENGTHS,
        help="comma-separated lengths, such as 10,20,50,100",
    )
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--runtime-repeats", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--text", help="experiment text entered directly")
    source.add_argument("--corpus", type=Path, default=None)
    parser.add_argument("--compare-methods", action="store_true")
    args = parser.parse_args()

    outputs = run_performance_experiments(
        lengths=args.lengths,
        trials=args.trials,
        runtime_repeats=args.runtime_repeats,
        seed=args.seed,
        corpus_path=args.corpus,
        compare_methods=args.compare_methods,
        corpus_text=args.text,
    )
    print("Experiments completed.")
    for name, path in outputs.items():
        if isinstance(path, list):
            for image_path in path:
                print(f"Chart: {image_path}")
        else:
            print(f"{name}: {path}")


if __name__ == "__main__":
    main()
