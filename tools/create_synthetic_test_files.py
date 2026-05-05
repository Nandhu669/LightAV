import os
import shutil

def create_synthetic_samples():
    benign_src = "data/benign/appidcertstorecheck.exe"
    synth_dir = "data/synthetic_malware"
    
    if not os.path.exists(synth_dir):
        os.makedirs(synth_dir)

    print("[*] Creating EICAR test file...")
    # EICAR standard test file
    eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open(os.path.join(synth_dir, "eicar.exe"), "w") as f:
        f.write(eicar_string)

    print("[*] Creating High-Entropy simulated packed malware...")
    # Read a benign executable
    if os.path.exists(benign_src):
        with open(benign_src, "rb") as f:
            benign_data = f.read()
        
        # Append 1 MB of highly random data (entropy ~ 8.0)
        # This simulates a packed overlay section without containing real malware code
        random_payload = b"LIGHTAV_SIMULATED_MALWARE_PAYLOAD_START" + os.urandom(1024 * 1024)
        
        with open(os.path.join(synth_dir, "synthetic_packed_overlay.exe"), "wb") as f:
            f.write(benign_data)
            f.write(random_payload)
            
        print("[+] Synthetic samples created successfully in data/synthetic_malware/")
    else:
        print(f"[-] Could not find benign source file: {benign_src}")

if __name__ == "__main__":
    create_synthetic_samples()
