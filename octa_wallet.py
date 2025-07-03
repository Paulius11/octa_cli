#!/usr/bin/env python3
"""
Octa Wallet Library
Core wallet functionality for Octa Network
"""

import json
import base64
import hashlib
import time
import re
import random
import asyncio
import aiohttp
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

import nacl.signing


class TransactionType(Enum):
    INCOMING = "in"
    OUTGOING = "out"


@dataclass
class WalletConfig:
    """Wallet configuration data structure"""
    private_key: str
    address: str
    rpc_url: str = "https://octra.network"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'priv': self.private_key,
            'addr': self.address,
            'rpc': self.rpc_url
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WalletConfig':
        return cls(
            private_key=data.get('priv', ''),
            address=data.get('addr', ''),
            rpc_url=data.get('rpc', 'https://octra.network')
        )


@dataclass
class Transaction:
    """Transaction data structure"""
    hash: str
    amount: float
    address: str
    tx_type: TransactionType
    timestamp: datetime
    nonce: int = 0
    epoch: int = 0
    message: Optional[str] = None
    confirmed: bool = True
    staging_status: Optional[str] = None
    pool_position: Optional[int] = None
    ou_cost: Optional[int] = None
    
    @property
    def is_pending(self) -> bool:
        return self.epoch == 0 or self.staging_status == "awaiting_epoch"
    
    @property
    def status_display(self) -> str:
        if self.staging_status == "awaiting_epoch":
            return "Staged (Pending)"
        elif self.is_pending:
            return "Pending"
        elif self.epoch:
            return f"Epoch {self.epoch}"
        else:
            return "Confirmed"


@dataclass
class WalletStatus:
    """Wallet status information"""
    balance: float
    nonce: int
    pending_transactions: int = 0
    last_updated: Optional[datetime] = None


class OctaWallet:
    """Core Octa wallet functionality"""
    
    MICRO_OCT = 1_000_000
    ADDRESS_PATTERN = re.compile(r"^oct[1-9A-HJ-NP-Za-km-z]{44}$")  # oct + 44 base58 chars = 47 total
    AMOUNT_PATTERN = re.compile(r"^\d+(\.\d+)?$")
    
    def __init__(self, config_path: str = "wallet.json"):
        self.config_path = Path(config_path)
        self.config: Optional[WalletConfig] = None
        self.signing_key: Optional[nacl.signing.SigningKey] = None
        self.public_key: Optional[str] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.wallet_status = WalletStatus(balance=0.0, nonce=0)
        self.transactions: List[Transaction] = []
        self.staged_transactions: List[Transaction] = []
        self.logger = logging.getLogger(__name__)
    
    def generate_new_wallet(self) -> WalletConfig:
        """Generate a new wallet with keys and address"""
        # Generate new wallet
        signing_key = nacl.signing.SigningKey.generate()
        private_key = base64.b64encode(signing_key.encode()).decode()
        pub_bytes = signing_key.verify_key.encode()
        
        # Use correct Octa address generation: oct + Base58(SHA256(pubkey))
        def base58_encode(data):
            alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
            if len(data) == 0:
                return ""
            
            num = int.from_bytes(data, 'big')
            encoded = ''
            while num > 0:
                num, remainder = divmod(num, 58)
                encoded = alphabet[remainder] + encoded
            
            # Handle leading zeros
            for i in range(len(data)):
                if data[i] != 0:
                    break
                encoded = '1' + encoded
            
            return encoded
        
        # Create address: oct + Base58(SHA256(publicKey))
        pub_hash = hashlib.sha256(pub_bytes).digest()
        address = 'oct' + base58_encode(pub_hash)
        
        # Create config
        config = WalletConfig(
            private_key=private_key,
            address=address,
            rpc_url="https://octra.network"
        )
        
        return config
    
    def save_wallet(self, config: WalletConfig, file_path: Optional[str] = None) -> bool:
        """Save wallet configuration to file"""
        try:
            path = Path(file_path) if file_path else self.config_path
            with open(path, 'w') as f:
                json.dump(config.to_dict(), f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save wallet: {e}")
            return False
    
    def load_wallet(self, file_path: Optional[str] = None) -> bool:
        """Load wallet configuration from file"""
        try:
            path = Path(file_path) if file_path else self.config_path
            
            if not path.exists():
                self.logger.error(f"Wallet file {path} not found!")
                return False
            
            with open(path, 'r') as f:
                data = json.load(f)
            
            self.config = WalletConfig.from_dict(data)
            
            if not self.config.private_key or not self.config.address:
                self.logger.error("Invalid wallet configuration - missing private key or address!")
                return False
            
            # Initialize cryptographic keys
            self.signing_key = nacl.signing.SigningKey(
                base64.b64decode(self.config.private_key)
            )
            self.public_key = base64.b64encode(
                self.signing_key.verify_key.encode()
            ).decode()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load wallet: {e}")
            return False
    
    def validate_address(self, address: str) -> bool:
        """Validate Octa address format"""
        return bool(self.ADDRESS_PATTERN.match(address))
    
    def validate_amount(self, amount_str: str) -> bool:
        """Validate amount format"""
        return bool(self.AMOUNT_PATTERN.match(amount_str))
    
    async def init_session(self):
        """Initialize HTTP session"""
        if not self.session or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(timeout=timeout)
    
    async def close_session(self):
        """Close HTTP session"""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
            except Exception as e:
                self.logger.error(f"Error closing session: {e}")
            finally:
                self.session = None
    
    async def make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict] = None,
        timeout: int = 10
    ) -> Tuple[int, str, Optional[Dict]]:
        """Make HTTP request to Octa network"""
        if not self.config:
            return 0, "No wallet loaded", None
        
        await self.init_session()
        
        try:
            url = f"{self.config.rpc_url}{endpoint}"
            
            async with getattr(self.session, method.lower())(
                url, 
                json=data if method == 'POST' else None,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                text = await response.text()
                
                try:
                    json_data = json.loads(text) if text else None
                except json.JSONDecodeError:
                    json_data = None
                
                return response.status, text, json_data
                
        except asyncio.TimeoutError:
            return 0, "Request timeout", None
        except Exception as e:
            self.logger.error(f"Request failed: {e}")
            return 0, str(e), None
    
    async def get_balance(self) -> Tuple[bool, float, int]:
        """Get wallet balance and nonce"""
        if not self.config:
            self.logger.error("No wallet configuration loaded")
            return False, 0.0, 0
        
        return await self.get_balance_for_address(self.config.address)
    
    async def get_balance_for_address(self, address: str) -> Tuple[bool, float, int]:
        """Get balance and nonce for any address"""
        try:
            status, text, json_data = await self.make_request(
                'GET', f'/balance/{address}', data=None, timeout=30
            )
            
            if status == 200 and json_data:
                balance = float(json_data.get('balance', 0))
                nonce = int(json_data.get('nonce', 0))
                return True, balance, nonce
            elif status == 404:
                # New wallet with no transactions
                return True, 0.0, 0
            else:
                self.logger.error(f"Unexpected status code: {status}, response: {text}")
                return False, 0.0, 0
                
        except Exception as e:
            self.logger.error(f"Failed to get balance for address {address}: {e}")
            return False, 0.0, 0
    
    async def get_transaction_history(self, limit: int = 100) -> Tuple[bool, List[Transaction]]:
        """Get transaction history"""
        if not self.config:
            return False, []
        
        try:
            status, text, json_data = await self.make_request(
                'GET', f'/address/{self.config.address}?limit={limit}'
            )
            
            if status == 200 and json_data and 'recent_transactions' in json_data:
                transactions = []
                tx_refs = json_data['recent_transactions']
                
                for ref in tx_refs:
                    tx_hash = ref['hash']
                    
                    # Get transaction details
                    tx_status, _, tx_data = await self.make_request(
                        'GET', f'/tx/{tx_hash}', timeout=5
                    )
                    
                    if tx_status == 200 and tx_data and 'parsed_tx' in tx_data:
                        parsed = tx_data['parsed_tx']
                        
                        is_incoming = parsed.get('to') == self.config.address
                        amount_raw = parsed.get('amount_raw', parsed.get('amount', '0'))
                        amount = (
                            float(amount_raw) if '.' in str(amount_raw) 
                            else int(amount_raw) / self.MICRO_OCT
                        )
                        
                        # Extract message if present
                        message = None
                        if 'data' in tx_data:
                            try:
                                data = json.loads(tx_data['data'])
                                message = data.get('message')
                            except json.JSONDecodeError:
                                pass
                        
                        transaction = Transaction(
                            hash=tx_hash,
                            amount=amount,
                            address=parsed.get('from') if is_incoming else parsed.get('to'),
                            tx_type=TransactionType.INCOMING if is_incoming else TransactionType.OUTGOING,
                            timestamp=datetime.fromtimestamp(parsed.get('timestamp', 0)),
                            nonce=parsed.get('nonce', 0),
                            epoch=ref.get('epoch', 0),
                            message=message
                        )
                        
                        transactions.append(transaction)
                
                return True, transactions
            elif status == 404:
                # No transactions yet
                return True, []
            else:
                return False, []
                
        except Exception as e:
            self.logger.error(f"Failed to get transaction history: {e}")
            return False, []
    
    def create_transaction(
        self, 
        to_address: str, 
        amount: float, 
        nonce: int,
        message: Optional[str] = None
    ) -> Tuple[Dict, str]:
        """Create a signed transaction"""
        if not self.config or not self.signing_key:
            raise ValueError("No wallet loaded")
        
        tx_data = {
            "from": self.config.address,
            "to_": to_address,
            "amount": str(int(amount * self.MICRO_OCT)),
            "nonce": int(nonce),
            "ou": "1" if amount < 1000 else "3",
            "timestamp": time.time() + random.random() * 0.01
        }
        
        if message:
            tx_data["message"] = message
        
        # Create signature
        sign_data = {k: v for k, v in tx_data.items() if k != "message"}
        blob = json.dumps(sign_data, separators=(",", ":"))
        
        signature = base64.b64encode(
            self.signing_key.sign(blob.encode()).signature
        ).decode()
        
        tx_data.update({
            "signature": signature,
            "public_key": self.public_key
        })
        
        tx_hash = hashlib.sha256(blob.encode()).hexdigest()
        
        return tx_data, tx_hash
    
    async def send_transaction(self, tx_data: Dict) -> Tuple[bool, str, float]:
        """Send transaction to network"""
        start_time = time.time()
        
        status, text, json_data = await self.make_request('POST', '/send-tx', tx_data)
        
        response_time = time.time() - start_time
        
        if status == 200:
            if json_data and json_data.get('status') == 'accepted':
                tx_hash = json_data.get('tx_hash', '')
                return True, tx_hash, response_time
            elif text.lower().startswith('ok'):
                tx_hash = text.split()[-1]
                return True, tx_hash, response_time
        
        error_msg = json.dumps(json_data) if json_data else text
        return False, error_msg, response_time
    
    async def send_octa(
        self, 
        to_address: str, 
        amount: float, 
        message: Optional[str] = None
    ) -> Tuple[bool, str]:
        """High-level method to send OCT"""
        try:
            # Validate inputs
            if not self.validate_address(to_address):
                return False, "Invalid recipient address"
            
            if amount <= 0:
                return False, "Amount must be greater than 0"
            
            # Get current balance and nonce
            success, balance, nonce = await self.get_balance()
            if not success:
                return False, "Failed to get wallet balance"
            
            if balance < amount:
                return False, f"Insufficient balance ({balance:.6f} < {amount:.6f})"
            
            # Create and send transaction
            tx_data, tx_hash = self.create_transaction(to_address, amount, nonce + 1, message)
            success, result, _ = await self.send_transaction(tx_data)
            
            if success:
                return True, f"Transaction sent: {result}"
            else:
                return False, f"Transaction failed: {result}"
                
        except Exception as e:
            self.logger.error(f"Failed to send transaction: {e}")
            return False, str(e)
    
    async def test_connection(self) -> bool:
        """Test connection to RPC server"""
        try:
            status, _, _ = await self.make_request('GET', '/staging', data=None, timeout=30)
            return status == 200
        except:
            return False


class OctaWalletCLI:
    """Command-line interface for Octa wallet"""
    
    def __init__(self):
        self.wallet = OctaWallet()
        # Setup basic logging
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    async def create_wallet_command(self, output_file: str = "wallet.json") -> bool:
        """Create a new wallet"""
        try:
            print("🔐 Generating new wallet...")
            config = self.wallet.generate_new_wallet()
            
            print(f"✅ Wallet generated!")
            print(f"Address: {config.address}")
            print(f"🔑 Private key saved to {output_file}")
            print("⚠️  Keep your private key secure!")
            
            success = self.wallet.save_wallet(config, output_file)
            if success:
                print(f"📁 Wallet saved to {output_file}")
                return True
            else:
                print("❌ Failed to save wallet")
                return False
                
        except Exception as e:
            print(f"❌ Error creating wallet: {e}")
            return False
    
    async def balance_command(self, wallet_file: str = "wallet.json", address: Optional[str] = None) -> bool:
        """Check wallet balance"""
        try:
            if address:
                # Check balance for specific address without loading wallet
                print(f"📍 Address: {address}")
                print("🔍 Checking balance...")
                
                # Create minimal config for the request
                if not self.wallet.config:
                    self.wallet.config = WalletConfig(
                        private_key="",
                        address=address,
                        rpc_url="https://octra.network"
                    )
                
                success, balance, nonce = await self.wallet.get_balance_for_address(address)
            else:
                # Use wallet file to get own balance
                if not self.wallet.load_wallet(wallet_file):
                    print(f"❌ Failed to load wallet from {wallet_file}")
                    return False
                
                print(f"📍 Address: {self.wallet.config.address}")
                print("🔍 Checking balance...")
                
                success, balance, nonce = await self.wallet.get_balance()
            
            if success:
                print(f"💰 Balance: {balance:.6f} OCT")
                print(f"🔢 Nonce: {nonce}")
                return True
            else:
                print("❌ Failed to get balance")
                return False
                
        except Exception as e:
            print(f"❌ Error checking balance: {e}")
            return False
    
    async def send_command(
        self, 
        to_address: str, 
        amount: float, 
        message: Optional[str] = None,
        wallet_file: str = "wallet.json"
    ) -> bool:
        """Send OCT to another address"""
        try:
            if not self.wallet.load_wallet(wallet_file):
                print(f"❌ Failed to load wallet from {wallet_file}")
                return False
            
            print(f"💸 Sending {amount:.6f} OCT to {to_address}")
            if message:
                print(f"📝 Message: {message}")
            
            success, result = await self.wallet.send_octa(to_address, amount, message)
            if success:
                print(f"✅ {result}")
                return True
            else:
                print(f"❌ {result}")
                return False
                
        except Exception as e:
            print(f"❌ Error sending transaction: {e}")
            return False
    
    async def history_command(self, wallet_file: str = "wallet.json", limit: int = 10) -> bool:
        """Show transaction history"""
        try:
            if not self.wallet.load_wallet(wallet_file):
                print(f"❌ Failed to load wallet from {wallet_file}")
                return False
            
            print("📜 Getting transaction history...")
            
            success, transactions = await self.wallet.get_transaction_history(limit)
            if not success:
                print("❌ Failed to get transaction history")
                return False
            
            if not transactions:
                print("📭 No transactions found")
                return True
            
            print(f"\n📊 Last {len(transactions)} transactions:")
            print("-" * 80)
            
            for tx in transactions:
                date_str = tx.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                type_str = "IN " if tx.tx_type == TransactionType.INCOMING else "OUT"
                amount_str = f"{tx.amount:.6f}"
                addr_str = tx.address[:20] + "..." if len(tx.address) > 23 else tx.address
                
                print(f"{date_str} | {type_str} | {amount_str:>12} OCT | {addr_str}")
                if tx.message:
                    print(f"             Message: {tx.message}")
                print()
            
            return True
                
        except Exception as e:
            print(f"❌ Error getting history: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup resources"""
        await self.wallet.close_session()