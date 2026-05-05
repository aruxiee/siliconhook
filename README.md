
# 🪝siliconhook: MitM on CPU Registers

## 🛡️ Overview
Unlike standard software hooks that overwrite memory with `JMP` instructions or `0xCC` opcodes, this hook leverages the processor's own hardware debug architecture ($DR0$-$DR7$) to intercept execution. This gives zero-footprint presence that remains invisible to code-integrity scanners, CRC checks, and EDR solutions that monitor for `.text` section modifications.

The tool forces the processor to pause and hand control to our script the moment a specific memory address is accessed by using hardware registers to hook the execution flow.

⚠️ **Please Note:** This project is strictly for **Educational and Authorized Penetration Testing**. I am not responsible for any of the shenanigans you guys pull.

---

## 🛠️ Binaries

We utilize two binaries to demonstrate the MitM cycle.

### 1. `victim.exe` (Any Target App)
Victim binary represents an application handling sensitive data. It typically contains:
*   **Target Function:** A routine (e.g., `CheckPassword` or `OpenFile`) that expects a specific data pointer in the `RCX` register.
*   **Blind Spot:** It operates under the assumption that register states and memory buffers remain constant between the function call and execution. It has no internal mechanism to detect that a hardware register has flagged its memory address for interception.

### 2. `siliconhook.exe` (Controller)
The main binary. It acts as a *Ghost Debugger* that:
*   **Attaches** to the victim process using the Win32 Debugging API.
*   **Arms** `siliconhook` by writing to the CPU's debug registers.
*   **Manipulates** the target app by overwriting memory buffers while the CPU is in a trap state.

---

## 💻 Logic & Workflow

`siliconhook` operates through a stop-modify-go workflow.

- **Process Attachment:** The script uses `DebugActiveProcess` to attach to the victim's PID. This allows the kernel to redirect thread exceptions to our controller.
- **Hardware Hook:** Using `SetThreadContext`, we place the target address in the **$DR0$** register and enable the $L0$ bit in **$DR7$**. This sets a hardware-level breakpoint that does not alter a single byte of the victim's code.
- **Interception (MitM):** When the victim thread hits the address, the CPU triggers an `EXCEPTION_SINGLE_STEP`. `siliconhook` now has a Man-in-the-Middle position, and is able to see and modify registers ($RIP, RCX, RAX, RSP$) before the victim instruction processes them.
- **Active Manipulation:** Using `WriteProcessMemory`, the data buffer pointed to by $RCX$ is poisoned.
- **Leverage:** We temporarily disable the hardware trap and set the **Trap Flag (TF)** in `EFLAGS`. This executes exactly one instruction in the victim.
- **Post-Audit:** Once the instruction completes, we check $RAX$ to see how the function reacted to our manipulated data before another go.

---

## 🧪 Testing & Execution

### Rust Environment Setup
Ensure your `Cargo.toml` includes the necessary Windows system features:
```toml
[dependencies]
windows-sys = { version = "0.52", features = [
    "Win32_System_Diagnostics_Debug",
    "Win32_System_Threading",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_Foundation",
    "Win32_System_Memory"
] }
```
I have included it with the rest. Just compile the project then: `cargo build --release`.

### Identification
- Run `victim.exe`.
- Note its **PID**.
- Identify the **Memory Address** of the target function (e.g., `0x7ff7232810d0`).

### Deployment
Run `siliconhook` from an Admin PowerShell (non-Admin works too but only for horizontally privileged apps).
```bash
./siliconhook.exe <PID> <Address>
```

### Step 4: Verification (Output)
When the function is triggered, `siliconhook` will output the following telemetry:

```text
[!] hook triggered.
    cpu at: 0x00007ff7bfc610d0       <-- rip (instruction pointer)
    rcx:    0x00007ffb0b6a1ce4 | rax: 0x0000000000000001
    >>> data at rcx (original):
        [hex]:  C3 CD 2E C3 0F 1F...  <-- sniffed binary data
        [utf8]: "original_data"       <-- ascii decode
        [wide]: "o r i g i n a l"     <-- windows wide string decode
    [+] injected payload into rcx buffer.
    >>> stack peek: [rsp]: 0x7ff7bfc610b5 | [rsp+8]: 0x0
    [?] post-tamper status: rax = 0x1    <-- victim accepted payload
```

---

## 📊 MITRE

| ID | Technique | Application |
| :--- | :--- | :--- |
| **T1055** | **Process Injection** | Overwriting arguments via `WriteProcessMemory` while the CPU is halted. |
| **T1574** | **Hijack Execution Flow** | Using hardware registers to redirect the Instruction Pointer ($RIP$). |
| **T1622** | **Debugger Evasion** | Using hardware traps to bypass software-based anti-debug checks. |
| **T1548** | **Abuse Elevation Control** | Bypassing auth logic by tampering with comparison registers. |

---

## 🕵️ Advanced Leverage

Researchers can leverage this hook for high-impact exploitation.

*   **Authentication Bypass:** Target `strcmp` or `memcmp`. When the trap hits, copy the *correct* password (found in $RDX$) into the "user" input ($RCX$). The comparison will always return **True**.
*   **EDR/AV Bypass:** Hook the reporting/telemetry function of a security agent. Upon trigger, manually set `ctx.Rip = [RSP]` (the return address). This teleports the CPU past the notification logic silencing the alert.
*   **TOCTOU Manipulation:** Wait for a program to validate a *Safe* file. Trigger the hook on the subsequent `CreateFile` call and swap the $RCX$ path to a malicious file *after* the safety check has already finished.

---
