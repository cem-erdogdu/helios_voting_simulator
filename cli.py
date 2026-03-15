"""
Interactive CLI for Cryptographic Voting Simulator

This module provides a command-line interface for running elections
interactively with voter registration, PIN authentication, ballot casting,
and individual verifiability.
"""

import sys
import getpass
from typing import Optional

from crypto import generate_keypair, Keypair, p
from trustees import create_trustees, combine_partial_decryptions
from zkp import encrypt_with_proof
from bulletin_board import create_board, BulletinBoard
from voter_registry import create_registry, VoterRegistry
from election_state import ElectionState, save_election, load_election, election_exists


class ElectionCLI:
    """
    Interactive command-line interface for the voting system.
    """
    
    def __init__(self):
        self.keypair: Optional[Keypair] = None
        self.registry: Optional[VoterRegistry] = None
        self.board: Optional[BulletinBoard] = None
        self.trustees = []
        self.threshold = 3
        self.num_trustees = 5
        self.voter_receipts: dict[str, str] = {}  # voter_id -> receipt
        self.election_name: str = "Election"
        self.state: ElectionState = ElectionState()
    
    def _save_state(self):
        """Save the current election state to file."""
        # Update state from current attributes
        self.state.election_name = self.election_name
        self.state.keypair = self.keypair
        self.state.registry = self.registry
        self.state.board = self.board
        self.state.trustees = self.trustees
        self.state.threshold = self.threshold
        self.state.num_trustees = self.num_trustees
        self.state.voter_receipts = self.voter_receipts
        
        if save_election(self.state):
            print(f"💾 Election saved.")
    
    def _load_state(self) -> bool:
        """Load election state from file if it exists."""
        loaded_state = load_election()
        if loaded_state:
            self.state = loaded_state
            # Update attributes from loaded state
            self.election_name = loaded_state.election_name
            self.keypair = loaded_state.keypair
            self.registry = loaded_state.registry
            self.board = loaded_state.board
            self.trustees = loaded_state.trustees
            self.threshold = loaded_state.threshold
            self.num_trustees = loaded_state.num_trustees
            self.voter_receipts = loaded_state.voter_receipts
            return True
        return False
    
    def _check_saved_election(self):
        """Check if there's a saved election and offer to load it."""
        if election_exists():
            print("\n📁 A saved election was found.")
            choice = self.get_input("Load saved election? (y/n)").lower()
            if choice == 'y':
                if self._load_state():
                    print(f"✅ Loaded election: {self.election_name}")
                    stats = self.state.get_stats()
                    print(f"   Registered voters: {stats['registered_voters']}")
                    print(f"   Ballots cast: {stats['ballots_cast']}")
                    return True
                else:
                    print("❌ Failed to load election.")
        return False
    
    def print_header(self, title: str):
        """Print a formatted header."""
        print("\n" + "=" * 60)
        print(title.center(60))
        print("=" * 60)
    
    def print_menu(self, title: str, options: list[tuple[str, str]]):
        """Print a menu with options."""
        self.print_header(title)
        for key, desc in options:
            print(f"  [{key}] {desc}")
        print("-" * 60)
    
    def get_input(self, prompt: str) -> str:
        """Get input from the user."""
        return input(f"{prompt}: ").strip()
    
    def get_password(self, prompt: str) -> str:
        """Get password/PIN input (hidden)."""
        return getpass.getpass(f"{prompt}: ").strip()
    
    def pause(self):
        """Pause and wait for user to continue."""
        input("\nPress Enter to continue...")
    
    def setup_election(self):
        """Set up a new election."""
        self.print_header("ELECTION SETUP")
        
        # Get election name
        name = self.get_input("Enter election name (or press Enter for 'Election')")
        if name:
            self.election_name = name
        
        print(f"\n📊 Setting up: {self.election_name}")
        
        # Generate keypair
        print("\n🔑 Generating election keypair...")
        self.keypair = generate_keypair()
        print(f"✓ Public key generated")
        print(f"  y = {self.keypair.y}")
        
        # Create voter registry
        print("\n📋 Creating voter registry...")
        self.registry = create_registry()
        print("✓ Voter registry created")
        
        # Create bulletin board
        print("\n📮 Creating bulletin board...")
        self.board = create_board(self.keypair.y, self.registry)
        print("✓ Bulletin board created with registration required")
        
        # Set up trustees
        print("\n🏛️ Setting up trustees...")
        self.threshold = int(self.get_input("Enter threshold (default: 3)") or "3")
        self.num_trustees = int(self.get_input("Enter number of trustees (default: 5)") or "5")
        
        q = (p - 1) // 2
        self.trustees = create_trustees(self.keypair.x, self.threshold, self.num_trustees, q)
        print(f"✓ {self.num_trustees} trustees created (threshold: {self.threshold})")
        
        print(f"\n✅ Election '{self.election_name}' is ready!")
        self._save_state()
        self.pause()
    
    def register_voters(self):
        """Register voters for the election."""
        if not self.registry:
            print("\n❌ Please set up an election first!")
            self.pause()
            return
        
        while True:
            self.print_menu("VOTER REGISTRATION", [
                ("1", "Register a new voter"),
                ("2", "View registered voters"),
                ("3", "Back to main menu")
            ])
            
            choice = self.get_input("Select an option")
            
            if choice == "1":
                voter_id = self.get_input("Enter voter ID (username)").lower()
                if not voter_id:
                    print("❌ Voter ID cannot be empty")
                    continue
                
                pin = self.get_password("Enter PIN (4-6 digits)")
                confirm_pin = self.get_password("Confirm PIN")
                
                if pin != confirm_pin:
                    print("❌ PINs do not match!")
                    continue
                
                success, message = self.registry.register_voter(voter_id, pin)
                if success:
                    print(f"✓ {message}")
                    self._save_state()
                else:
                    print(f"❌ {message}")
            
            elif choice == "2":
                voters = self.registry.get_registered_voters()
                print(f"\n📋 Registered Voters ({len(voters)}):")
                if voters:
                    for voter in sorted(voters):
                        voted = "✓ Voted" if self.board and self.board.has_voted(voter) else "○ Not voted"
                        print(f"  • {voter} ({voted})")
                else:
                    print("  (No voters registered yet)")
            
            elif choice == "3":
                break
    
    def cast_ballot(self):
        """Cast a ballot (voting phase)."""
        if not self.board or not self.registry:
            print("\n❌ Please set up an election first!")
            self.pause()
            return
        
        if self.registry.get_voter_count() == 0:
            print("\n❌ No voters registered yet!")
            self.pause()
            return
        
        self.print_header("CAST BALLOT")
        
        # Authenticate voter
        voter_id = self.get_input("Enter your voter ID").lower()
        pin = self.get_password("Enter your PIN")
        
        success, message = self.registry.authenticate_voter(voter_id, pin)
        if not success:
            print(f"❌ {message}")
            self.pause()
            return
        
        print(f"✓ {message}")
        
        # Check if already voted
        if self.board.has_voted(voter_id):
            print("❌ You have already cast a ballot!")
            self.pause()
            return
        
        # Get vote
        print("\n🗳️ Cast your vote:")
        print("  [0] No (0)")
        print("  [1] Yes (1)")
        
        vote_str = self.get_input("Enter your choice (0 or 1)")
        if vote_str not in ("0", "1"):
            print("❌ Invalid choice! Must be 0 or 1.")
            self.pause()
            return
        
        vote = int(vote_str)
        
        # Encrypt vote with proof
        print("\n🔒 Encrypting your vote...")
        ciphertext, proof, _ = encrypt_with_proof(vote, self.keypair.y)
        
        # Post to bulletin board
        success, message, receipt = self.board.post_ballot(voter_id, ciphertext, proof)
        
        if success:
            print(f"✓ {message}")
            print(f"\n📜 Your ballot receipt: {receipt}")
            print("  (Save this to verify your ballot was counted!)")
            self.voter_receipts[voter_id] = receipt
            self._save_state()
        else:
            print(f"❌ {message}")
        
        self.pause()
    
    def verify_ballot(self):
        """Verify a ballot using its receipt."""
        if not self.board:
            print("\n❌ Please set up an election first!")
            self.pause()
            return
        
        self.print_header("VERIFY BALLOT")
        
        receipt = self.get_input("Enter your ballot receipt")
        if not receipt:
            print("❌ Receipt cannot be empty")
            self.pause()
            return
        
        found, message = self.board.verify_ballot_by_receipt(receipt)
        print(message)
        
        self.pause()
    
    def tally_election(self):
        """Tally the election results."""
        if not self.board or not self.keypair:
            print("\n❌ Please set up an election first!")
            self.pause()
            return
        
        if self.board.get_voter_count() == 0:
            print("\n❌ No ballots have been cast!")
            self.pause()
            return
        
        self.print_header("ELECTION TALLY")
        
        # Show election stats
        print(f"\n📊 Election Statistics:")
        print(f"  Registered voters: {self.registry.get_voter_count()}")
        print(f"  Ballots cast: {self.board.get_voter_count()}")
        print(f"  Participation: {100 * self.board.get_voter_count() // self.registry.get_voter_count()}%")
        
        # Verify election
        print("\n🔍 Verifying election integrity...")
        is_valid, report = self.board.verify_election()
        print(report)
        
        if not is_valid:
            print("\n❌ Election verification failed!")
            self.pause()
            return
        
        # Get combined ciphertext
        combined = self.board.get_combined_ciphertext()
        
        # Threshold decryption
        print(f"\n🔓 Threshold Decryption ({self.threshold} of {self.num_trustees} trustees)")
        print("Simulating trustee collaboration...")
        
        # Select first t trustees for demonstration
        participating = self.trustees[:self.threshold]
        print(f"Participating trustees: {[t.index for t in participating]}")
        
        # Collect partial decryptions
        q = (p - 1) // 2
        partials = [t.decrypt_partial(combined, q) for t in participating]
        
        # Combine partial decryptions
        tally = combine_partial_decryptions(combined, partials, q)
        
        # Show results
        print("\n" + "=" * 60)
        print("ELECTION RESULTS".center(60))
        print("=" * 60)
        print(f"\n🎉 {self.election_name} Results:")
        print(f"  Total votes cast: {self.board.get_voter_count()}")
        print(f"  'Yes' votes: {tally}")
        print(f"  'No' votes: {self.board.get_voter_count() - tally}")
        print("=" * 60)
        
        self.pause()
    
    def audit_election(self):
        """Audit the election (public verification)."""
        if not self.board:
            print("\n❌ Please set up an election first!")
            self.pause()
            return
        
        self.print_header("ELECTION AUDIT")
        
        print("\n📋 Public Audit Information:")
        print(f"  Total ballots: {self.board.get_voter_count()}")
        
        # Show all receipts (public)
        receipts = self.board.get_receipts()
        print(f"\n📜 Public Receipts ({len(receipts)} total):")
        for i, receipt in enumerate(receipts[:10], 1):
            print(f"  {i}. {receipt}")
        if len(receipts) > 10:
            print(f"  ... and {len(receipts) - 10} more")
        
        # Show entries
        print("\n🗳️ Ballot Entries:")
        for entry in self.board.get_entries():
            print(f"  • {entry.voter_id}: receipt={entry.receipt[:16]}...")
        
        # Full verification
        print("\n🔍 Running full verification...")
        is_valid, report = self.board.verify_election()
        print(report)
        
        self.pause()
    
    def reset_election(self):
        """Reset the election and clear saved state."""
        import os
        self.print_header("RESET ELECTION")
        confirm = self.get_input("Are you sure you want to reset? This will delete all data! (yes/no)")
        if confirm.lower() == "yes":
            if election_exists():
                os.remove("election.json")
            self.__init__()  # Reset all attributes
            print("✅ Election has been reset.")
        else:
            print("Reset cancelled.")
        self.pause()
    
    def run(self):
        """Run the main CLI loop."""
        # Check for saved election on startup
        self._check_saved_election()
        
        while True:
            self.print_menu("CRYPTOGRAPHIC VOTING SYSTEM", [
                ("1", "Setup Election"),
                ("2", "Register Voters"),
                ("3", "Cast Ballot"),
                ("4", "Verify My Ballot"),
                ("5", "Tally Election"),
                ("6", "Audit Election"),
                ("R", "Reset Election"),
                ("Q", "Quit")
            ])
            
            choice = self.get_input("Select an option").upper()
            
            if choice == "1":
                self.setup_election()
            elif choice == "2":
                self.register_voters()
            elif choice == "3":
                self.cast_ballot()
            elif choice == "4":
                self.verify_ballot()
            elif choice == "5":
                self.tally_election()
            elif choice == "6":
                self.audit_election()
            elif choice == "R":
                self.reset_election()
            elif choice == "Q":
                print("\n👋 Goodbye!")
                break
            else:
                print("❌ Invalid option!")


def main():
    """Main entry point for the CLI."""
    print("\n" + "=" * 60)
    print("Welcome to the Cryptographic Voting System".center(60))
    print("=" * 60)
    print("\nThis system provides:")
    print("  • Voter registration with PIN authentication")
    print("  • Encrypted ballot casting with zero-knowledge proofs")
    print("  • Individual verifiability via ballot receipts")
    print("  • Threshold decryption by multiple trustees")
    print("  • Full election auditability")
    print("\nAll cryptography is done locally for educational purposes.")
    
    cli = ElectionCLI()
    cli.run()


if __name__ == "__main__":
    main()
