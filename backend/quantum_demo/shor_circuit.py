import os
import json
import base64
import math
from fractions import Fraction

try:
    import numpy as np
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
    from qiskit import transpile
    from qiskit.visualization import plot_histogram
    import matplotlib
    matplotlib.use('Agg')
    QISKIT_AVAILABLE = True
except ImportError:
    QISKIT_AVAILABLE = False

def c_amod15(a, power):
    """Controlled multiplication by a mod 15"""
    if a not in [2, 7, 8, 11, 13]:
        raise ValueError("'a' must be 2,7,8,11 or 13")
    U = QuantumCircuit(4)
    for _iteration in range(power):
        if a in [2, 13]:
            U.swap(2, 3)
            U.swap(1, 2)
            U.swap(0, 1)
        if a in [7, 8]:
            U.swap(0, 1)
            U.swap(1, 2)
            U.swap(2, 3)
        if a in [4, 11]:
            U.swap(1, 3)
            U.swap(0, 2)
        if a in [7, 11, 13]:
            for q in range(4):
                U.x(q)
    U = U.to_gate()
    U.name = f"{a}^{power} mod 15"
    c_U = U.control()
    return c_U

def c_amodN(a, power, N):
    """Generic controlled multiplication by a mod N using unitary matrix"""
    n_target = int(np.ceil(np.log2(N)))
    size = 2**n_target
    U = np.zeros((size, size))
    for i in range(size):
        if i < N:
            target = (i * (a**power)) % N
            U[target, i] = 1
        else:
            U[i, i] = 1
    
    qc = QuantumCircuit(n_target)
    qc.unitary(U, range(n_target))
    c_U = qc.to_gate().control()
    c_U.name = f"{a}^{power} mod {N}"
    return c_U

def qft_dagger(n):
    """n-qubit QFTdagger the first n qubits in circ"""
    qc = QuantumCircuit(n)
    for qubit in range(n // 2):
        qc.swap(qubit, n - qubit - 1)
    for j in range(n):
        for m in range(j):
            qc.cp(-np.pi / float(2**(j - m)), m, j)
        qc.h(j)
    qc.name = "QFT†"
    return qc

def build_shor_circuit(a: int):
    """Builds the full Shor's algorithm circuit for factoring N=15 using base a."""
    N = 15
    n_count = 8  # number of counting qubits
    qc = QuantumCircuit(n_count + 4, n_count)
    
    # Initialize counting qubits in state |+>
    for q in range(n_count):
        qc.h(q)
        
    # Auxiliary register in state |1>
    qc.x(n_count)
    
    # Apply controlled modular exponentiation
    for q in range(n_count):
        qc.append(c_amod15(a, 2**q), [q] + [i + n_count for i in range(4)])
        
    # Apply inverse QFT
    qc.append(qft_dagger(n_count), range(n_count))
    
    # Measure counting qubits
    qc.measure(range(n_count), range(n_count))
    
    return qc

def build_generic_shor_circuit(N: int, a: int):
    """Builds a generic Shor's algorithm circuit for factoring N using base a."""
    if not QISKIT_AVAILABLE:
        raise ImportError("Qiskit is required to build circuits.")
        
    n_target = int(np.ceil(np.log2(N)))
    n_count = 2 * n_target  # standard counting qubits for 2L
    qc = QuantumCircuit(n_count + n_target, n_count)
    
    for q in range(n_count):
        qc.h(q)
        
    qc.x(n_count) # state |1>
    
    for q in range(n_count):
        qc.append(c_amodN(a, 2**q, N), [q] + list(range(n_count, n_count + n_target)))
        
    qc.append(qft_dagger(n_count), range(n_count))
    qc.measure(range(n_count), range(n_count))
    
    return qc

def run_shor_circuit(a: int) -> dict:
    """Runs the circuit, exports visualizations, and returns the measurement counts."""
    qc = build_shor_circuit(a)
    
    # 1. Export Circuit Diagram
    try:
        qc.draw(output='mpl', filename='shor_circuit.png', fold=-1)
    except Exception as e:
        print(f"Warning: Could not draw circuit: {e}")
    
    # Use AerSimulator
    simulator = AerSimulator()
    compiled_circuit = transpile(qc, simulator)
    
    # Execute
    result = simulator.run(compiled_circuit, shots=1000).result()
    counts = result.get_counts()
    
    # Format labels for the histogram to make them readable
    formatted_counts = {}
    for bitstring, count in counts.items():
        phase_int = int(bitstring, 2)
        if phase_int == 0:
            formatted_counts["phase 0/4"] = count
        elif phase_int == 64:
            formatted_counts["phase 1/4"] = count
        elif phase_int == 128:
            formatted_counts["phase 2/4"] = count
        elif phase_int == 192:
            formatted_counts["phase 3/4"] = count
        else:
            # optionally group noise or ignore for the clean plot
            pass

    # 2. Export Histogram
    try:
        import matplotlib.pyplot as plt
        # Increase figsize slightly to give more room
        fig = plot_histogram(formatted_counts, figsize=(8, 5))
        
        # Rotate labels slightly and ensure they fit
        ax = fig.axes[0]
        ax.tick_params(axis='x', rotation=15, labelsize=11)
        fig.tight_layout()
        
        fig.savefig('shor_histogram.png')
        plt.close(fig)
    except Exception as e:
        print(f"Warning: Could not plot histogram: {e}")
        
    return counts

def load_fallback():
    fallback_path = os.path.join(os.path.dirname(__file__), "fallback.json")
    if os.path.exists(fallback_path):
        with open(fallback_path, "r") as f:
            return json.load(f)
    return {
        "factors": [],
        "circuit_base64": None,
        "histogram_base64": None,
        "error": "Simulation failed and no fallback available"
    }

def execute_shor():
    if not QISKIT_AVAILABLE:
        print("Qiskit not available, returning fallback")
        return load_fallback()

    try:
        N = 15
        a = 7
        n_count = 8
        counts = run_shor_circuit(a)
        
        sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        factors_found = set()
        
        for phase_str, _ in sorted_counts:
            phase_int = int(phase_str, 2)
            if phase_int == 0:
                continue
                
            phase = phase_int / (2**n_count)
            frac = Fraction(phase).limit_denominator(N)
            r = frac.denominator
            
            if r % 2 != 0:
                continue
                
            guess1 = math.gcd(a**(r//2) - 1, N)
            guess2 = math.gcd(a**(r//2) + 1, N)
            
            for guess in [guess1, guess2]:
                if guess not in [1, N] and (N % guess) == 0:
                    factors_found.add(guess)
                    
            if len(factors_found) >= 2:
                break
                
        # Read the images and convert to base64
        circuit_b64 = ""
        histogram_b64 = ""
        try:
            with open("shor_circuit.png", "rb") as f:
                circuit_b64 = base64.b64encode(f.read()).decode('utf-8')
            with open("shor_histogram.png", "rb") as f:
                histogram_b64 = base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            print(f"Warning: Could not read image files: {e}")

        return {
            "factors": list(factors_found),
            "circuit_base64": f"data:image/png;base64,{circuit_b64}" if circuit_b64 else None,
            "histogram_base64": f"data:image/png;base64,{histogram_b64}" if histogram_b64 else None
        }
    except Exception as e:
        print(f"Error in quantum simulation: {e}")
        return load_fallback()

