import time
import re
import mmh3
import math
from collections import Counter

LOG_FILE = "lms-stage-access.log"

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

class HyperLogLog:
    def __init__(self, p=5):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E

def load_ips_from_log(file_path):
    """Завантажує IP-адреси з лог-файлу, ігноруючи некоректні рядки."""
    ips = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            match = IP_PATTERN.search(line)
            if match:
                ips.append(match.group())
    return ips

def count_unique_exact(ips):
    """Точний підрахунок унікальних IP-адрес."""
    return len(set(ips))

def count_unique_hyperloglog(ips):
    """Наближений підрахунок унікальних IP-адрес за допомогою HyperLogLog."""
    hll = HyperLogLog(p=10)
    for ip in ips:
        hll.add(ip)
    return hll.count()

def main():
    # Завантаження даних
    start_time = time.time()
    ips = load_ips_from_log(LOG_FILE)
    load_time = time.time() - start_time

    # Точний підрахунок
    start_time = time.time()
    exact_count = count_unique_exact(ips)
    exact_time = time.time() - start_time

    # Підрахунок через HyperLogLog
    start_time = time.time()
    hll_count = count_unique_hyperloglog(ips)
    hll_time = time.time() - start_time

    # Вивід результатів
    print("\nРезультати порівняння:")
    print("{:<30} {:<20} {:<20}".format("Метод", "Точний підрахунок", "HyperLogLog"))
    print("-" * 70)
    print("{:<30} {:<20} {:<20}".format("Унікальні елементи", exact_count, hll_count))
    print("{:<30} {:<20.4f} {:<20.4f}".format("Час виконання (сек.)", exact_time, hll_time))

if __name__ == "__main__":
    main()
