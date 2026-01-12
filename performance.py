# performance.py – AES vs ChaCha Performance Module (Final)
import time
import matplotlib.pyplot as plt
import crypto
import os
import json
import numpy as np

PERF_FILE = "performance_log.json"


# ------------------ Measure Function ------------------
def measure_time(func, *args, **kwargs):
    """Measure execution time of a function"""
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    elapsed = end - start
    return result, elapsed


# ------------------ Log Performance Data ------------------
def _save_perf_record(data):
    """Append timing results to JSON log"""
    existing = []
    if os.path.exists(PERF_FILE):
        with open(PERF_FILE, "r") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []
    existing.append(data)
    with open(PERF_FILE, "w") as f:
        json.dump(existing, f, indent=4)


# ------------------ Run Performance Test ------------------
def test_algorithms():
    """Run AES and ChaCha performance comparison"""
    sample_data = os.urandom(1_000_000)  # 1 MB random data
    aes_key = crypto.aes_generate_key()
    chacha_key = crypto.chacha20_generate_key()

    # AES test
    _, aes_enc_time = measure_time(crypto.encrypt_aes_gcm, aes_key, sample_data)
    aes_blob, _ = crypto.encrypt_aes_gcm(aes_key, sample_data)
    _, aes_dec_time = measure_time(crypto.decrypt_aes_gcm, aes_key, aes_blob)

    # ChaCha test
    _, chacha_enc_time = measure_time(crypto.encrypt_chacha, chacha_key, sample_data)
    chacha_blob, _ = crypto.encrypt_chacha(chacha_key, sample_data)
    _, chacha_dec_time = measure_time(crypto.decrypt_chacha, chacha_key, chacha_blob)

    result = {
        "aes_encrypt": aes_enc_time,
        "aes_decrypt": aes_dec_time,
        "chacha_encrypt": chacha_enc_time,
        "chacha_decrypt": chacha_dec_time,
    }

    _save_perf_record(result)
    return result


# ------------------ Bar Graph Display ------------------
def show_bar_graph():
    """Display performance comparison as a bar chart"""
    result = test_algorithms()

    # Prepare data
    algorithms = ['AES Encrypt', 'AES Decrypt', 'ChaCha Encrypt', 'ChaCha Decrypt']
    times = [
        result["aes_encrypt"],
        result["aes_decrypt"],
        result["chacha_encrypt"],
        result["chacha_decrypt"]
    ]

    # Bar colors and labels
    colors = ['#4CAF50', '#2196F3', '#FF9800', '#9C27B0']
    xpos = np.arange(len(algorithms))

    plt.figure(figsize=(8, 5))
    bars = plt.bar(xpos, times, color=colors, width=0.5)
    plt.xticks(xpos, algorithms, fontsize=11)
    plt.ylabel("Time (seconds)", fontsize=12)
    plt.title("AES vs ChaCha20 Encryption/Decryption Performance", fontsize=13, weight="bold")
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Annotate bar values
    for bar, time_val in zip(bars, times):
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.001,
                 f"{time_val:.4f}s", ha='center', fontsize=10, color='black', weight='bold')

    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    show_bar_graph()
