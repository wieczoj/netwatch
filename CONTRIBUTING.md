# Contributing to NetWatch

First off, **thank you** for considering contributing to NetWatch! 🎉

This document provides guidelines for contributing to the project. Following these helps maintain quality and makes the review process smoother.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Guidelines](#coding-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Testing](#testing)
- [License](#license)

---

## Code of Conduct

This project follows a simple code of conduct:

- 🤝 **Be respectful** — disagreement is fine, disrespect is not
- 🌍 **Be inclusive** — everyone is welcome regardless of background
- 💬 **Be constructive** — criticism should help, not hurt
- 🐛 **Focus on the issue, not the person**

Unacceptable behavior will result in interaction restrictions.

---

## How Can I Contribute?

### 🐛 Reporting Bugs

Before creating a bug report:
1. **Check existing [issues](https://github.com/wieczoj/netwatch/issues)** — your bug might already be reported
2. **Use the latest version** — check if the bug exists in the current main branch
3. **Try to reproduce** — make sure it's reproducible

When creating a bug report, include:
- **System info**: distro, kernel version (`uname -r`), compositor (picom/xcompmgr/etc.)
- **Steps to reproduce** the issue
- **Expected behavior** vs **actual behavior**
- **Logs**: output from `sudo ./netwatch` (without `-q`)
- **Screenshots** if applicable (especially for GUI issues)

### ✨ Suggesting Features

Feature requests are welcome! Please:
1. **Check [Discussions](https://github.com/wieczoj/netwatch/discussions)** first
2. **Open a Discussion** before creating an Issue
3. **Describe the use case** — why is this needed?
4. **Consider implementation** — how might it work?

### 📖 Improving Documentation

Documentation improvements are highly valued:
- Fix typos
- Clarify confusing sections
- Add examples
- Translate to other languages (open a Discussion first)

### 💻 Contributing Code

See [Pull Request Process](#pull-request-process) below.

---

## Development Setup

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install -y build-essential libbpf-dev libgtk-3-dev \
    libcairo2-dev libx11-dev clang llvm bpftool \
    libelf-dev zlib1g-dev pkg-config

# Optional but recommended
sudo apt install -y gdb valgrind cppcheck

Build from source

git clone https://github.com/wieczoj/netwatch.git
cd netwatch
make

Project structure

netwatch/
├── netwatch.c          # Main userspace code (MIT)
├── netwatch.bpf.c      # eBPF kernel code (GPL v2)
├── Makefile            # Build configuration
├── vmlinux.h           # Auto-generated kernel types (gitignored)
├── docs/               # Documentation and screenshots
├── LICENSE             # MIT License
├── SECURITY.md         # Security policy
└── README.md           # Main documentation

Common development tasks

# Clean build
make clean && make

# Run with debug output
sudo ./netwatch

# Run with custom flags
sudo ./netwatch -d out -q

# Test help/about (no sudo needed)
./netwatch --help
./netwatch --about

Coding Guidelines
General principles
Keep it simple — prefer clarity over cleverness
Comment why, not what — code shows what, comments explain why
Match existing style — consistency matters
One change per commit — easier to review and revert

C Code Style (netwatch.c)

// 4 spaces indentation, no tabs
// K&R brace style
// snake_case for functions and variables
// UPPER_CASE for #define constants

static void example_function(int parameter) {
    if (parameter > 0) {
        do_something();
    } else {
        do_something_else();
    }
}

eBPF Code Style (netwatch.bpf.c)
Must remain GPL v2 compatible
Use BPF_CORE_READ for portability (CO-RE)
Keep programs simple — kernel verifier rejects complex logic
Always handle null pointers
Document any kernel function dependencies

Adding new features
Before implementing a major feature:

Open a Discussion to discuss the approach
Get feedback on design before coding
Update documentation as part of the same PR
Add example to README if user-facing

Commit Messages
Follow the Conventional Commits specification:

<type>(<scope>): <subject>

<body>

<footer>


Types
feat: New feature
fix: Bug fix
docs: Documentation only
style: Code style (formatting, missing semicolons, etc.)
refactor: Code refactoring (no functional change)
perf: Performance improvement
test: Adding or updating tests
chore: Maintenance (version bumps, etc.)

Examples
# Good
git commit -m "feat: Add UDP connection monitoring"
git commit -m "fix: Handle IPv6 addresses in format_ip()"
git commit -m "docs: Update README with macOS instructions"

# Bad
git commit -m "update"
git commit -m "fixed stuff"
git commit -m "wip"

Detailed message example

feat: Add process whitelist filtering

Allow users to ignore connections from specified processes via
--whitelist option. Useful for filtering out background services
like systemd-resolved and chronyd.

- Add --whitelist CLI flag accepting comma-separated process names
- Implement whitelist check in handle_event()
- Add tests for whitelist parsing
- Update --help and README

Closes #42

Pull Request Process
Before submitting
✅ Fork the repository
✅ Create a branch with descriptive name:
git checkout -b feature/add-udp-support
git checkout -b fix/ipv6-formatting
git checkout -b docs/install-instructions

✅ Make your changes following coding guidelines
✅ Test thoroughly on your system
✅ Update documentation (README, comments, etc.)
✅ Commit with clear messages
✅ Push to your fork

Submitting the PR
Open a Pull Request from your branch to main
Title: clear and descriptive (follows commit message format)
Description: include:
What changes were made
Why they were necessary
How to test them
Screenshots (for GUI changes)
Reference any related issues (Closes #42)

What happens next?
✅ Maintainer reviews within a week (best effort)
💬 Feedback may be provided
🔄 Address requested changes
✅ Once approved, PR is merged

PR Requirements
✅ Code compiles without warnings (make succeeds)
✅ Functionality is tested
✅ Documentation is updated
✅ Commit messages follow convention
✅ No breaking changes (or clearly marked if necessary)

Testing
NetWatch doesn't have automated tests yet (contributions welcome!). Manual testing checklist:

Basic functionality
 make clean && make builds without errors
 sudo ./netwatch starts without errors
 Overlay window appears (semi-transparent)
 curl http://example.com generates a log entry
 Window is always on top
 Ctrl+C exits cleanly

CLI options
 ./netwatch --help shows help (no sudo needed)
 ./netwatch --about shows project info
 sudo ./netwatch -q runs without debug output
 sudo ./netwatch -d out filters only outbound
 sudo ./netwatch -d in filters only inbound

Keyboard shortcuts
 1 shows all (BOTH)
 2 shows IN only
 3 shows OUT only
 Q exits the program


Connection tracking
 Successful connection shows OK status
 Failed connection (curl http://1.2.3.4:9999 --max-time 3) shows FAIL
 Color coding works (red for port 22/80/443, green for high ports)

License
By contributing to NetWatch, you agree that:

📜 Userspace code (netwatch.c) will be licensed under MIT
📜 eBPF code (netwatch.bpf.c) will be licensed under GPL v2 (required by Linux kernel)
📜 You have the right to contribute the code (it's yours or properly licensed)
📜 Your contributions will be publicly attributed in commit history

See LICENSE for full text.

Questions?
💬 General questions: GitHub Discussions
🐛 Bug reports: GitHub Issues
🔒 Security issues: See SECURITY.md
📧 Other inquiries: konradverse@gmail.com


💝 Support Development
Beyond code, you can support NetWatch by:

⭐ Starring the repository
🐦 Sharing on social media
💝 Donating via Ko-fi
📝 Writing about it (blog posts, tutorials)
🐛 Reporting bugs you encounter
💡 Sharing ideas in Discussions

Thank you for contributing! 🙏

Every contribution, no matter how small, is valued and appreciated.


