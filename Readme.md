### Rust-shellcode-injection

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![Platform](https://img.shields.io/badge/platform-windows-blueviolet)
![License](https://img.shields.io/github/license/joaoviictorti/RustRedOps)
</br>

A simple example of shellcode injection in Rust using [[winapi]](https://docs.rs/winapi/0.3.9/winapi/)

* The Notepad process is created in suspended mode.
* Memory is allocated within the Notepad process for the shellcode.
* The shellcode is written into the allocated memory space.
eg : https://github.com/boku7/x64win-DynamicNoNull-WinExec-PopCalc-Shellcode
* An asynchronous procedure call (APC) function is used to execute the shellcode.
* The Notepad process thread is then resumed to start executing the shellcode.

**Installation git**
```bash
cargo install --git https://github.com/Maherilaza/rust-shellcode-injection
```

**Build manually**
```bash
git clone https://github.com/Maherilaza/rust-shellcode-injection

cd rust-shellcode-injection

cargo build --release
```

**How to use**
```rust

use shellcode::utils::{*};
fn main() {

    let shellcode: [u8; SHELLOCODE_LEN] = [
        /*shellcode*/
    ];

    let mut my_shellcode : Ushellcode = Ushellcode::new_shellcod(
        shellcode
    );

    my_shellcode.inject();
}

```