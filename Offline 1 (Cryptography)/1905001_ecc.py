import random
import time
import importlib

crypto_helper = importlib.import_module("1905001_crypto_helper")


def generate_ecc_curve_params(prime_size):
    """
    Curve Equation: y^2 = x^3 + ax + b mod p
    Non-singularity condition: 4a^3 + 27b^2 != 0 mod p
    prime_size: 128, 192 or 256 bits
    Returns: a, b, x, y, p
    """
    p = int(crypto_helper.generate_prime(prime_size) or 0)

    while True:
        # Choose random x, y, a
        x = random.randint(1, 100)
        y = random.randint(1, 100)
        a = random.randint(1, 100)

        b = (y**2 - x**3 - a*x) % p
        while b < 0:
            b += p

        if (4*a**3 + 27*b**2) % p != 0:
            break

    return a, b, x, y, p


def ec_point_addition(p1, p2, a, b, p):
    """
    Does both point addition or doubling depending on whether p1 == p2
    """
    if p1[0] == p2[0] and p1[1] == p2[1]:
        # Point doubling
        s = ((3 * p1[0]**2 + a) * pow(2 * p1[1], -1, p)) % p
    else:
        # Point addition
        s = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, p)) % p

    x3 = (s**2 - p1[0] - p2[0]) % p
    y3 = (s * (p1[0] - x3) - p1[1]) % p
    return (x3, y3)


def point_multiplication(point, d, a, b, p):
    """
    Use binary exponentiation to perform point multiplication
    """
    res = point
    d >>= 1
    while d > 0:
        res = ec_point_addition(res, res, a, b, p)
        if d & 1:
            res = ec_point_addition(res, point, a, b, p)
        d >>= 1
    return res


def generate_keys(point, a, b, p, prime_size):
    """
    Generates a pair of private and public keys for elliptic curve cryptography
    """
    private_key = random.getrandbits(prime_size)
    public_key = point_multiplication(point, private_key, a, b, p)
    return (private_key, public_key)


def generate_shared_secret_key(other_public_key, own_private_key, a, b, p):
    """
    Generates the shared secret key for elliptic curve cryptography (ECC)
    """
    shared_secret_key = point_multiplication(
        other_public_key, own_private_key, a, b, p)
    return shared_secret_key


trial_count = 5
time_measures = dict()

if __name__ == "__main__":
    for mode in [128, 192, 256]:
        A_total_time, B_total_time, R_total_time = 0, 0, 0
        print("k = ", mode)
        print()
        for trial in range(trial_count):
            print("Trial: ", trial + 1)
            a, b, x, y, p = generate_ecc_curve_params(mode)
            print("Curve equation: y^2 = x^3 + {}x + {} mod {}".format(a, b, p))
            print("Base point: ({}, {})".format(x, y))

            # Person 1
            # Generate the private and public keys
            t1 = time.time()
            private_key1, public_key1 = generate_keys((x, y), a, b, p, mode)
            A_total_time += time.time() - t1
            print("Person 1's private key:", private_key1)
            print("Person 1's public key: ({} {})".format(
                public_key1[0], public_key1[1]))

            # Person 2
            # Generate the private and public keys
            t1 = time.time()
            private_key2, public_key2 = generate_keys((x, y), a, b, p, mode)
            B_total_time += time.time() - t1
            print("Person 2's private key:", private_key2)
            print("Person 2's public key: ({} {})".format(
                public_key2[0], public_key2[1]))

            # Shared secret key for Person 1
            t1 = time.time()
            shared_secret_key1 = generate_shared_secret_key(
                public_key2, private_key1, a, b, p)
            R_total_time += time.time() - t1

            # Shared secret key for Person 2
            t1 = time.time()
            shared_secret_key2 = generate_shared_secret_key(
                public_key1, private_key2, a, b, p)
            R_total_time += time.time() - t1

            print("Shared secret key from Person 1:", shared_secret_key1[0])
            print("Shared secret key from Person 2:", shared_secret_key2[0])

        time_measures[mode] = (A_total_time / trial_count, B_total_time /
                               trial_count, R_total_time / (2 * trial_count))
        time_measures[mode] = [1000 * x for x in time_measures[mode]]

        print()

    print("Computation Time Measurements: (in ms)")
    print("k\t\tA\t\t\tB\t\t\tR")
    print("128\t\t{}\t{}\t{}".format(
        time_measures[128][0], time_measures[128][1], time_measures[128][2]))
    print("192\t\t{}\t{}\t{}".format(
        time_measures[192][0], time_measures[192][1], time_measures[192][2]))
    print("256\t\t{}\t{}\t{}".format(
        time_measures[256][0], time_measures[256][1], time_measures[256][2]))
