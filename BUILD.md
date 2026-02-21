# Building EasyPCAP

## Pre-Built Binaries

### Windows 64-bit
- **File**: `easypcap-windows-amd64.exe`
- **Size**: 4.5 MB
- **Requirements**: None (standalone executable)
- **Usage**: `.\easypcap-windows-amd64.exe -f capture.pcap -html`

### Linux 64-bit
Linux binaries require libpcap to be installed on the target system. Build instructions below.

---

## Building from Source

### Prerequisites

#### All Platforms
- Go 1.20 or higher
- Git

#### Linux/macOS
- libpcap-dev (Debian/Ubuntu) or libpcap-devel (RHEL/CentOS)

```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# RHEL/CentOS/Fedora
sudo yum install libpcap-devel

# macOS
brew install libpcap
```

### Build Instructions

#### Clone Repository
```bash
git clone https://github.com/bidhata/PCaptor.git
cd PCaptor
```

#### Build for Current Platform
```bash
go build -o easypcap
```

#### Build with Optimizations
```bash
# Smaller binary size
go build -ldflags="-s -w" -o easypcap
```

### Cross-Compilation

#### Windows 64-bit (from any platform)
```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o easypcap-windows-amd64.exe
```

#### Linux 64-bit (from Linux)
```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o easypcap-linux-amd64
```

#### macOS 64-bit (from macOS)
```bash
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o easypcap-darwin-amd64
```

#### Linux ARM64 (Raspberry Pi, etc.)
```bash
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o easypcap-linux-arm64
```

### Build Flags Explained

- `-ldflags="-s -w"`: Strip debug information and symbol table (smaller binary)
- `-o <name>`: Output file name
- `GOOS`: Target operating system
- `GOARCH`: Target architecture

---

## Linux Build Instructions (Detailed)

### Ubuntu/Debian

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y git golang-go libpcap-dev

# Clone and build
git clone https://github.com/bidhata/PCaptor.git
cd PCaptor
go build -ldflags="-s -w" -o pcaptor-linux-amd64

# Make executable
chmod +x pcaptor-linux-amd64

# Test
./pcaptor-linux-amd64 -version
```

### RHEL/CentOS/Fedora

```bash
# Install dependencies
sudo yum install -y git golang libpcap-devel

# Clone and build
git clone https://github.com/bidhata/PCaptor.git
cd PCaptor
go build -ldflags="-s -w" -o pcaptor-linux-amd64

# Make executable
chmod +x pcaptor-linux-amd64

# Test
./pcaptor-linux-amd64 -version
```

### Arch Linux

```bash
# Install dependencies
sudo pacman -S git go libpcap

# Clone and build
git clone https://github.com/bidhata/PCaptor.git
cd PCaptor
go build -ldflags="-s -w" -o pcaptor-linux-amd64

# Make executable
chmod +x pcaptor-linux-amd64

# Test
./pcaptor-linux-amd64 -version
```

---

## Docker Build (Alternative)

If you want to build Linux binaries without installing dependencies:

### Dockerfile
```dockerfile
FROM golang:1.20-alpine AS builder

RUN apk add --no-cache git libpcap-dev gcc musl-dev

WORKDIR /build
COPY . .

RUN go build -ldflags="-s -w" -o easypcap-linux-amd64

FROM alpine:latest
RUN apk add --no-cache libpcap

COPY --from=builder /build/easypcap-linux-amd64 /usr/local/bin/easypcap

ENTRYPOINT ["easypcap"]
```

### Build and Extract
```bash
# Build Docker image
docker build -t easypcap-builder .

# Extract binary
docker create --name temp easypcap-builder
docker cp temp:/usr/local/bin/easypcap ./easypcap-linux-amd64
docker rm temp
```

---

## Verification

### Check Binary
```bash
# Windows
.\easypcap-windows-amd64.exe -version

# Linux/macOS
./easypcap-linux-amd64 -version
```

### Expected Output
```
PCaptor v2.0.0
Author: Krishnendu Paul (@bidhata)
Website: https://krishnendu.com
GitHub: https://github.com/bidhata/PCaptor
```

---

## Troubleshooting

### Issue: "libpcap not found" (Linux)
**Solution**: Install libpcap-dev
```bash
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel    # RHEL/CentOS
```

### Issue: "permission denied" (Linux)
**Solution**: Make binary executable
```bash
chmod +x easypcap-linux-amd64
```

### Issue: Cross-compilation fails
**Solution**: Build on target platform or use Docker

### Issue: Binary too large
**Solution**: Use build flags
```bash
go build -ldflags="-s -w" -o easypcap
```

---

## Binary Sizes

| Platform | Size | Notes |
|----------|------|-------|
| Windows 64-bit | ~4.5 MB | Standalone, no dependencies |
| Linux 64-bit | ~5.5 MB | Requires libpcap installed |
| macOS 64-bit | ~5.5 MB | Requires libpcap installed |

---

## Development Build

For development with debug symbols:

```bash
go build -o easypcap
```

For production with optimizations:

```bash
go build -ldflags="-s -w" -o easypcap
```

---

## Author

**Krishnendu Paul** (@bidhata)
- Website: https://krishnendu.com
- GitHub: https://github.com/bidhata/PCaptor
