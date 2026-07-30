import sys
import os

# Add the backend dir to sys.path so we can import classification
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from classification.risk_classifier import _score_key_size

def test_rsa_monotonicity():
    sizes = [1024, 2048, 3072, 4096, 6144, 8192]
    scores = [_score_key_size("RSA", size) for size in sizes]
    
    print(f"RSA Key Size Sub-Scores: {list(zip(sizes, scores))}")
    
    # Assert monotonic decreasing
    for i in range(len(scores) - 1):
        assert scores[i] >= scores[i+1], f"Monotonicity failed between {sizes[i]} and {sizes[i+1]}"
        
    # Assert clamped beyond anchor
    assert scores[-1] == 10.0, "Did not clamp to 10.0 at 8192"
    assert scores[-2] == 10.0, "Did not clamp to 10.0 at 6144"
    print("Monotonicity test passed!")

if __name__ == "__main__":
    test_rsa_monotonicity()
