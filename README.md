# 🛠 Manual DLL Injector / Manual Mapping Library

A lightweight **C++ manual-mapping DLL injector** for educational purposes and PE loading experimentation. This project is designed to help you **learn how manual mapping works in Windows** and understand the internals of PE files.

---

## ⚡ Features

- Manual mapping of DLLs into target processes  
- Handles PE **relocations**, **imports**, **TLS callbacks**, and **entry point execution**  
- Supports both **x86** and **x64** architectures  
- Optional clearing of headers and unused sections for stealth testing  
- Adjustable memory protections for remote process sections  
- Detailed logging for easier debugging  
- Pure **C++ implementation** without external dependencies  

---

## 📝 Requirements

- **Windows 7 / 8 / 10 / 11**  
- **C++17** compatible compiler (**MSVC recommended**)  

---

## 🚀 Usage

1. Build the project in **Visual Studio** or any C++17 compatible compiler.  
2. Run the injector with the target process ID and DLL path as arguments.  
3. Observe detailed logs for debugging and learning purposes.  

---

## ⚠️ Disclaimer

This project is for **educational purposes only**. Do not use it for illegal activities or malware development. The author is **not responsible** for misuse.

---

## 📚 Learning Resources

- [PE Format Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)  
- [Windows Internals Book](https://docs.microsoft.com/en-us/sysinternals/)