# Limitations

This document enumerates the technical limitations of LightAV as a static-analysis-only, user-space prototype.

---

## Detection Capabilities

| Capability | Status | Reason |
|---|---|---|
| Known malware (hash match) | Supported | Exact SHA-256/MD5 match against 60,011-entry database. Effective only for previously catalogued samples. |
| YARA signature match | Supported | Byte-pattern matching against 7 compiled rule files. Limited to patterns present in the ruleset. |
| PE structural anomalies | Supported | 20 heuristic rules evaluate header fields, section attributes, and import tables. Covers known-suspicious indicators only. |
| ML-based classification | Supported | LightGBM classifier on 77 PE header features. Accuracy is bounded by training data coverage and feature representation. |
| Zero-day detection | Limited | No signature exists for unknown threats. Detection depends on whether the sample triggers heuristic rules or deviates from the ML model's learned feature distribution. Novel attack vectors with benign-looking PE structure will evade all layers. |
| Polymorphic malware | Weak | Hash lookup fails on every new variant. YARA rules match only if static byte patterns survive mutation. Heuristic and ML layers may detect structural anomalies, but polymorphic engines that preserve normal PE structure defeat both. |
| Packed binaries | Partial | YARA rules detect known packer signatures (UPX, Themida, ASPack). Entropy-based heuristics flag high-entropy sections. Custom or unknown packers that produce normal entropy profiles are not detected. Unpacking is not performed — analysis operates on the packed binary only. |
| Fileless malware | Not supported | The engine requires a file on disk to scan. Memory-resident payloads, PowerShell-only execution, WMI persistence, and registry-stored shellcode are entirely outside the detection scope. |
| Runtime/behavioral analysis | Not supported | No process monitoring, API hooking, system call interception, or sandbox execution. Threats that manifest only during execution — such as process injection, credential dumping, or lateral movement — are not observable. |
| Kernel-level inspection | Not supported | The engine runs in user space. It cannot inspect kernel memory, intercept driver loading, or detect rootkits operating below the OS API layer. |
| Cloud threat intelligence | Not supported | No integration with VirusTotal, cloud sandboxes, or external threat feeds. All detection is performed against locally stored signatures, rules, and models. Hash database updates require manual import. |
| Encrypted payloads | Not supported | Encrypted or obfuscated payloads that decrypt only at runtime cannot be analyzed. Static analysis sees only the encrypted byte stream, which may appear as high-entropy data but yields no structural insight. |
| Document-based threats | Not supported | Malicious macros in Office documents, PDF exploits, and HTML/JS payloads are not analyzed by the heuristic or ML layers. YARA string rules provide minimal coverage only. |
| Script-based threats | Partial | YARA string-matching rules may detect known malicious patterns in `.bat`, `.ps1`, `.vbs` files. No script deobfuscation, AST analysis, or execution tracing is performed. |
| Anti-analysis evasion | Limited | YARA rules detect known anti-debug and anti-VM techniques by static pattern. Techniques that activate only at runtime (timing checks, environment fingerprinting via API calls) are not observable. |
| Adversarial ML evasion | Not evaluated | The ML classifier has not been tested against adversarial perturbation of PE features. Crafted binaries that manipulate header fields to fall within the model's benign decision boundary may evade detection. |

---

## Operational Constraints

| Constraint | Detail |
|---|---|
| Platform | Windows only. PE file analysis, service wrapper, and self-protection mechanisms are Windows-specific. |
| Privilege | Full self-protection and service installation require administrator privileges. |
| Update mechanism | None. Hash database, YARA rules, and ML model must be updated manually. |
| Concurrency | Single-machine, single-instance design. No distributed scanning or centralized management. |
| Validation | All testing performed on a single development machine. Cross-system reproducibility has not been verified. |
