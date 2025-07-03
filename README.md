# Octa CLI (Unofficial)

> ⚠️ **DISCLAIMER**: This is an **unofficial, community-developed** tool for Octa Network. It is **NOT** affiliated with or endorsed by the official Octa Network team. Use at your own risk.

A command-line interface for the Octa Network cryptocurrency.

## Installation

Requires Python 3.7+ and the following dependencies:
```bash
pip install aiohttp nacl
```

## Quick Start

1. **Create a new wallet:**
   ```bash
   python3 octa_cli.py create
   ```

2. **Check your balance:**
   ```bash
   python3 octa_cli.py balance
   ```

3. **Check any address balance:**
   ```bash
   python3 octa_cli.py balance oct1ABC...XYZ
   ```

4. **Send OCT:**
   ```bash
   python3 octa_cli.py send oct1ABC...XYZ 10.5
   python3 octa_cli.py send oct1ABC...XYZ 5.0 "Hello!"
   ```

5. **View transaction history:**
   ```bash
   python3 octa_cli.py history
   python3 octa_cli.py history --limit 50
   ```

## Commands

| Command | Description | Example |
|---------|-------------|---------|
| `create` | Create new wallet | `octa_cli.py create -o my_wallet.json` |
| `balance` | Check balance | `octa_cli.py balance [address]` |
| `send` | Send OCT | `octa_cli.py send <address> <amount> [message]` |
| `history` | Transaction history | `octa_cli.py history --limit 10` |
| `test` | Test network connection | `octa_cli.py test` |
| `--version` | Show version | `octa_cli.py --version` |

## Options

- `--wallet <file>` or `-w <file>`: Specify wallet file (default: wallet.json)
- `--help` or `-h`: Show help message

## Examples

```bash
# Create wallet with custom name
python3 octa_cli.py create --output my_wallet.json

# Use specific wallet file
python3 octa_cli.py --wallet my_wallet.json balance

# Send with message
python3 octa_cli.py send oct7bStm4yehrHkwnyTH34tcttGrDXFVaTGDn6XYT3zBUzr 1.5 "Payment"

# Check balance of any address (no wallet file needed)
python3 octa_cli.py balance oct7bStm4yehrHkwnyTH34tcttGrDXFVaTGDn6XYT3zBUzr
```

## Files

- `octa_cli.py` - Main CLI application
- `octa_wallet.py` - Core wallet functionality
- `wallet.json` - Default wallet file (created after running `create`)

## Network

Connected to: `https://octra.network`

## Version

Current version: 0.0.1