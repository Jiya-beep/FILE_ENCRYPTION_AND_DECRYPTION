import os
import crypto, performance

# Create dummy data of increasing size (in bytes)
sizes_kb = [10, 50, 100, 200, 500]
aes_times = []
chacha_times = []

for kb in sizes_kb:
    data = os.urandom(kb * 1024)
    key_aes = crypto.aes_generate_key()
    key_chacha = crypto.chacha20_generate_key()

    _, t1 = performance.measure_time(crypto.encrypt_aes_gcm, key_aes, data)
    _, t2 = performance.measure_time(crypto.encrypt_chacha, key_chacha, data)

    aes_times.append(t1)
    chacha_times.append(t2)

performance.plot_comparison(sizes_kb, aes_times, chacha_times)
