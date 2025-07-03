#!/usr/bin/env python3
"""
Wallet Generator for Octa Network Client
Creates a new wallet.json file with cryptographic keys
"""

import json
import base64
import hashlib
import nacl.signing
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

def generate_wallet():
    """Generate a new wallet with keys and address"""
    console = Console()
    
    console.print(Panel(
        "Octa Wallet Generator",
        title="Create New Wallet",
        border_style="blue"
    ))
    
    # Generate new signing key
    signing_key = nacl.signing.SigningKey.generate()
    
    # Get private key (base64 encoded)
    private_key = base64.b64encode(signing_key.encode()).decode()
    
    # Get public key (base64 encoded)
    public_key = base64.b64encode(signing_key.verify_key.encode()).decode()
    
    # Generate address from public key
    pub_bytes = signing_key.verify_key.encode()
    hash1 = hashlib.sha256(pub_bytes).digest()
    hash2 = hashlib.sha256(hash1).digest()
    
    # Create address with oct prefix and base58 encoding
    import base58
    address = "oct" + base58.b58encode(hash2).decode()
    
    # Default RPC endpoint
    rpc_url = "https://octra.network"
    
    # Display wallet info
    console.print("\n[bold green]New wallet generated![/bold green]")
    console.print(f"Address: {address}")
    console.print(f"Public Key: {public_key}")
    console.print(f"[red]Private Key: {private_key}[/red]")
    console.print(f"RPC URL: {rpc_url}")
    
    console.print("\n[yellow]⚠️  Important Security Notes:[/yellow]")
    console.print("• Keep your private key secret and secure")
    console.print("• Never share your private key with anyone")
    console.print("• Back up your wallet.json file safely")
    console.print("• This is a testnet wallet - tokens have no value")
    
    if Confirm.ask("\nSave this wallet to wallet.json?"):
        wallet_data = {
            "priv": private_key,
            "addr": address,
            "rpc": rpc_url
        }
        
        try:
            with open("wallet.json", "w") as f:
                json.dump(wallet_data, f, indent=2)
            
            console.print("[bold green]✓ Wallet saved to wallet.json[/bold green]")
            console.print("You can now run: python3 octa_client.py")
            
        except Exception as e:
            console.print(f"[red]Error saving wallet: {e}[/red]")
    else:
        console.print("[yellow]Wallet not saved[/yellow]")

if __name__ == "__main__":
    try:
        generate_wallet()
    except ImportError as e:
        if "base58" in str(e):
            print("Missing dependency: pip install base58")
        else:
            print(f"Missing dependency: {e}")
    except Exception as e:
        print(f"Error: {e}")