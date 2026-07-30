import math
from fractions import Fraction
from shor_circuit import run_shor_circuit

def run_test():
    N = 15
    a = 7
    n_count = 8
    
    print(f"Factoring N = {N} using Shor's Algorithm")
    print(f"Chosen base value 'a' = {a} (coprime to {N})")
    
    print("\nRunning quantum phase estimation circuit on AerSimulator...")
    counts = run_shor_circuit(a)
    
    # Sort the measurement outcomes by frequency
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    
    print("\nMeasurement Results (Top 5):")
    for phase_str, count in sorted_counts[:5]:
        phase_int = int(phase_str, 2)
        phase = phase_int / (2**n_count)
        print(f"  Measured string: {phase_str} (int {phase_int}), Phase: {phase:.4f}, Count: {count}")
        
    print("\nExtracting period 'r' and computing factors...")
    
    factors_found = set()
    
    for phase_str, _ in sorted_counts:
        phase_int = int(phase_str, 2)
        if phase_int == 0:
            continue
            
        phase = phase_int / (2**n_count)
        # Find convergent fraction with denominator < N
        frac = Fraction(phase).limit_denominator(N)
        r = frac.denominator
        
        # Check if we found a valid period
        if r % 2 != 0:
            continue
            
        # Compute potential factors
        guess1 = math.gcd(a**(r//2) - 1, N)
        guess2 = math.gcd(a**(r//2) + 1, N)
        
        for guess in [guess1, guess2]:
            if guess not in [1, N] and (N % guess) == 0:
                factors_found.add(guess)
                print(f"  -> Valid period r = {r} found from phase {phase:.4f}")
                print(f"  -> Non-trivial factor found: {guess}")
                
        if len(factors_found) == 2:
            break
            
    if factors_found:
        print(f"\nSUCCESS! Found factors of {N}: {list(factors_found)}")
    else:
        print(f"\nFAILED to find factors of {N} in this run.")

if __name__ == "__main__":
    run_test()
