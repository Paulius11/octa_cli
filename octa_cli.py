#!/usr/bin/env python3
"""
Octa CLI - Command Line Interface for Octa Network
Uses the octa_wallet library for all operations
"""

import asyncio
import argparse
import sys
from octa_wallet import OctaWalletCLI

__version__ = "0.0.1"


async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Octa Network Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s create                           # Create new wallet
  %(prog)s balance                          # Check own wallet balance
  %(prog)s balance oct1ABC...XYZ            # Check balance of specific address
  %(prog)s send oct1ABC...XYZ 10.5          # Send 10.5 OCT
  %(prog)s send oct1ABC...XYZ 5.0 "Hello"   # Send with message
  %(prog)s history                          # Show transaction history
  %(prog)s history --limit 50               # Show last 50 transactions
        """
    )
    
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    parser.add_argument(
        '--wallet', '-w',
        default='wallet.json',
        help='Wallet file path (default: wallet.json)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create wallet command
    create_parser = subparsers.add_parser('create', help='Create a new wallet')
    create_parser.add_argument(
        '--output', '-o',
        default='wallet.json',
        help='Output file for new wallet (default: wallet.json)'
    )
    
    # Balance command
    balance_parser = subparsers.add_parser('balance', help='Check wallet balance')
    balance_parser.add_argument(
        'address', 
        nargs='?', 
        help='Address to check balance for (optional, uses wallet file if not provided)'
    )
    
    # Send command
    send_parser = subparsers.add_parser('send', help='Send OCT to another address')
    send_parser.add_argument('address', help='Recipient address')
    send_parser.add_argument('amount', type=float, help='Amount to send')
    send_parser.add_argument('message', nargs='?', help='Optional message')
    
    # History command
    history_parser = subparsers.add_parser('history', help='Show transaction history')
    history_parser.add_argument(
        '--limit', '-l',
        type=int,
        default=10,
        help='Number of transactions to show (default: 10)'
    )
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test connection to network')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Initialize CLI
    cli = OctaWalletCLI()
    
    try:
        if args.command == 'create':
            success = await cli.create_wallet_command(args.output)
            return 0 if success else 1
            
        elif args.command == 'balance':
            success = await cli.balance_command(args.wallet, args.address)
            return 0 if success else 1
            
        elif args.command == 'send':
            success = await cli.send_command(
                args.address, 
                args.amount, 
                args.message, 
                args.wallet
            )
            return 0 if success else 1
            
        elif args.command == 'history':
            success = await cli.history_command(args.wallet, args.limit)
            return 0 if success else 1
            
        elif args.command == 'test':
            if not cli.wallet.load_wallet(args.wallet):
                print(f"❌ Failed to load wallet from {args.wallet}")
                return 1
            
            print("🔍 Testing connection...")
            success = await cli.wallet.test_connection()
            if success:
                print("✅ Connection successful!")
                return 0
            else:
                print("❌ Connection failed!")
                return 1
        
        else:
            parser.print_help()
            return 1
            
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1
    finally:
        await cli.cleanup()


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n🛑 Interrupted")
        sys.exit(1)