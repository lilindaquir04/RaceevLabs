#include <iostream>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <set>

using namespace std;

typedef unsigned long long uint64;


const uint64 P = 2179;   // простое число 
const uint64 G = 28;    // первообразный корень по модулю P 
const uint64 N = 129;    // число участников (≤ P−1)
const uint64 T = 55;    // порог (2 ≤ T ≤ N)



bool is_prime(uint64 n) {
    if (n < 2) return false;
    for (uint64 i = 2; i * i <= n; ++i)
        if (n % i == 0) return false;
    return true;
}


// g — первообразен ⇔ g^((p-1)/q) ≠ 1 (mod p) для всех простых q | (p-1)
bool is_primitive_root(uint64 g, uint64 p) {
    if (g == 0 || g >= p) return false;
    uint64 phi = p - 1;
    set<uint64> prime_factors;
    uint64 temp = phi;
    for (uint64 d = 2; d * d <= temp; ++d) {
        if (temp % d == 0) {
            prime_factors.insert(d);
            while (temp % d == 0) temp /= d;
        }
    }
    if (temp > 1) prime_factors.insert(temp);

    uint64 mod_exp = 1;
    for (uint64 q : prime_factors) {
        // Возводим g в степень (p-1)/q mod p
        uint64 exp = phi / q;
        mod_exp = 1;
        uint64 base = g % p;
        while (exp > 0) {
            if (exp & 1) mod_exp = (mod_exp * base) % p;
            base = (base * base) % p;
            exp >>= 1;
        }
        if (mod_exp == 1) return false;
    }
    return true;
}


int main() {
    setlocale(LC_ALL, "Ru");

    // === Проверка корректности параметров ===
    if (!is_prime(P)) {
        cerr << "Ошибка: P = " << P << " не является простым числом!\n";
        return 1;
    }
    if (!is_primitive_root(G, P)) {
        cerr << "Внимание: G = " << G << " НЕ является первообразным корнем по модулю P = " << P << "!\n";
        cerr << "Работа возможна, но вычисления через дискретные логарифмы могут давать ошибки.\n";
        return 1;
    }
    if (N > P - 1) {
        cerr << "Ошибка: N = " << N << " > P-1 = " << (P - 1) << ". Невозможно иметь больше участников, чем ненулевых x_i.\n";
        return 1;
    }
    if (T < 2 || T > N) {
        cerr << "Ошибка: T = " << T << " должно удовлетворять 2 ≤ T ≤ N = " << N << "\n";
        return 1;
    }

    cout << "Параметры:\n";
    cout << "  P = " << P << " (простое)\n";
    cout << "  G = " << G << " (первообразный корень)\n";
    cout << "  N = " << N << " участников\n";
    cout << "  T = " << T << "-пороговая схема\n\n";

    // === Ввод секрета с клавиатуры ===
    uint64 S;
    cout << "Введите секрет S (целое число, 0 ≤ S < " << P << "): ";
    while (!(cin >> S) || S >= P) {
        cout << " Некорректный ввод. Введите целое число в диапазоне [0, " << (P - 1) << "]: ";
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
    }

    // === Построение таблиц: deg_g[0..2P-2], log[0..P-1] ===
    vector<uint64> deg_g(2 * P - 1);
    vector<uint64> log(P, 0);

    deg_g[0] = 1 % P;
    for (uint64 i = 1; i < P; ++i) {
        deg_g[i] = (G * deg_g[i - 1]) % P;
        deg_g[P - 1 + i] = deg_g[i];
        log[deg_g[i]] = i;
    }

    // === Генерация коэффициентов многочлена ===
    srand(static_cast<unsigned>(time(nullptr)));
    vector<uint64> a(T);
    a[0] = S;
    for (uint64 i = 1; i < T; ++i) {
        a[i] = rand() % P;  // теперь можно и 0 — безопасно
    }

    // Вывод многочлена
    cout << "\nL(x) = " << a[0];
    for (uint64 i = 1; i < T; ++i) {
        if (a[i] == 0) continue;
        cout << " + " << a[i] << "·x^" << i;
    }
    cout << " (mod " << P << ")\n\n";

    // === Разделение секрета ===
    vector<uint64> y(N);
    for (uint64 i = 0; i < N; ++i) {
        uint64 x_val = i + 1;
        y[i] = a[0];
        uint64 x_pow = 1;
        for (uint64 j = 1; j < T; ++j) {
            x_pow = deg_g[log[x_pow] + log[x_val]];
            if (a[j] != 0) {
                uint64 term = deg_g[log[a[j]] + log[x_pow]];
                y[i] = (y[i] + term) % P;
            }
        }
        cout << "Доля участника " << x_val << ": L(" << x_val << ") = " << y[i] << "\n";
    }
    cout << "\n";

    // === Восстановление по первым T участникам ===
    vector<uint64> xs(T), ys(T);
    for (uint64 i = 0; i < T; ++i) {
        xs[i] = i + 1;
        ys[i] = y[i];
    }

    uint64 recovered_S = 0;
    for (uint64 i = 0; i < T; ++i) {
        uint64 prod = 1;
        for (uint64 j = 0; j < T; ++j) {
            if (j == i) continue;
            uint64 diff = (P + xs[j] - xs[i]) % P;
            if (diff == 0) {
                cerr << "Коллизия: x_i = x_j при i=" << i << ", j=" << j << "\n";
                return 1;
            }
            uint64 b = deg_g[log[xs[j]] + (P - 1) - log[diff]];
            prod = deg_g[log[prod] + log[b]];
        }
        recovered_S = (recovered_S + deg_g[log[ys[i]] + log[prod]]) % P;
    }

    cout << "Восстановленный секрет: S = " << recovered_S << "\n";
    cout << "Исходный секрет:       S = " << S << "\n";
    cout << (recovered_S == S ? " Успешно!" : " Ошибка!") << "\n";

    return 0;
}