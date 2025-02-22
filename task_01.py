import hashlib
import mmh3
import bitarray

class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        self.size = size
        self.num_hashes = num_hashes
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)

    def _hashes(self, item: str):
        """Генерує `num_hashes` хешів для заданого рядка."""
        hash_values = []
        for i in range(self.num_hashes):
            hash_value = mmh3.hash(item, i) % self.size
            hash_values.append(hash_value)
        return hash_values

    def add(self, item: str):
        """Додає елемент у фільтр Блума."""
        for hash_value in self._hashes(item):
            self.bit_array[hash_value] = 1

    def __contains__(self, item: str) -> bool:
        """Перевіряє, чи може елемент бути у фільтрі Блума."""
        return all(self.bit_array[hash_value] for hash_value in self._hashes(item))

def check_password_uniqueness(bloom_filter: BloomFilter, passwords: list[str]) -> dict[str, str]:
    """Перевіряє список паролів на унікальність за допомогою фільтра Блума."""
    results = {}
    for password in passwords:
        if not isinstance(password, str) or not password.strip():
            results[password] = "некоректний пароль"
        elif password in bloom_filter:
            results[password] = "вже використаний"
        else:
            results[password] = "унікальний"
            bloom_filter.add(password)
    return results

if __name__ == "__main__":
    # Ініціалізація фільтра Блума
    bloom = BloomFilter(size=1000, num_hashes=3)

    # Додавання існуючих паролів
    existing_passwords = ["password123", "admin123", "qwerty123"]
    for password in existing_passwords:
        bloom.add(password)

    # Перевірка нових паролів
    new_passwords_to_check = ["password123", "newpassword", "admin123", "guest"]
    results = check_password_uniqueness(bloom, new_passwords_to_check)

    # Виведення результатів
    for password, status in results.items():
        print(f"Пароль '{password}' — {status}.")
