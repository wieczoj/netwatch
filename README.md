cat > ~/data/02_PROJEKTY/NetWatch/README.md << 'EOF'
# NetWatch - Network Connection Monitor

Real-time TCP connection monitor with semi-transparent overlay.

## Build
```bash
make
Run
Bash
￼
sudo ./netwatch
Requirements
Linux kernel 5.8+ with BTF
Compositor (picom/xcompmgr/compton)
Root privileges (eBPF)
Test
Bash
￼
curl http://example.com
EOF

text
￼

### `.gitignore`

```bash
cat > ~/data/02_PROJEKTY/NetWatch/.gitignore << 'EOF'
# Compiled files
netwatch
netwatch.bpf.o
vmlinux.h
*.o

# Editor files
*~
.*.swp
.vscode/
.idea/
EOF
