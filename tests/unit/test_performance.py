"""Performance tests for secator runners.

Tests high-volume output processing scenarios like mapcidr on large CIDR ranges.
"""
import time
import unittest

from secator.runners import Command
from secator.output_types import Ip


class MockHighVolumeCommand(Command):
    """Mock command that simulates high-volume output like mapcidr."""
    cmd = 'seq'
    input_required = False
    output_types = [Ip]
    
    @staticmethod
    def item_loader(self, line):
        """Generate IP outputs from sequential numbers."""
        if line.strip().isdigit():
            num = int(line.strip())
            ip = f"10.{(num // 65536) % 256}.{(num // 256) % 256}.{num % 256}"
            yield {'ip': ip, 'alive': False}


class TestPerformance(unittest.TestCase):
    """Test performance of high-volume output processing."""
    
    def test_high_volume_output_1000_items(self):
        """Test processing 1000 items meets performance targets."""
        count = 1000
        target_throughput = 500  # items/sec (conservative target)
        
        start_time = time.time()
        
        cmd = MockHighVolumeCommand(
            print_line=False,
            print_item=False,
            print_stat=False,
            process=True
        )
        cmd.cmd = f'seq 1 {count}'
        results = list(cmd.run())
        
        elapsed = time.time() - start_time
        ip_results = [r for r in results if isinstance(r, Ip)]
        
        self.assertEqual(len(ip_results), count, f"Expected {count} IP results")
        
        throughput = len(ip_results) / elapsed
        self.assertGreaterEqual(
            throughput, 
            target_throughput,
            f"Throughput {throughput:.0f} items/sec is below target {target_throughput} items/sec"
        )
    
    def test_high_volume_output_5000_items(self):
        """Test processing 5000 items meets performance targets."""
        count = 5000
        target_throughput = 500  # items/sec (conservative target)
        
        start_time = time.time()
        
        cmd = MockHighVolumeCommand(
            print_line=False,
            print_item=False,
            print_stat=False,
            process=True
        )
        cmd.cmd = f'seq 1 {count}'
        results = list(cmd.run())
        
        elapsed = time.time() - start_time
        ip_results = [r for r in results if isinstance(r, Ip)]
        
        self.assertEqual(len(ip_results), count, f"Expected {count} IP results")
        
        throughput = len(ip_results) / elapsed
        self.assertGreaterEqual(
            throughput, 
            target_throughput,
            f"Throughput {throughput:.0f} items/sec is below target {target_throughput} items/sec"
        )
    
    def test_output_string_efficiency(self):
        """Test that output string building uses efficient list-based approach."""
        count = 100
        
        cmd = MockHighVolumeCommand(
            print_line=False,
            print_item=False,
            print_stat=False,
            process=True
        )
        cmd.cmd = f'seq 1 {count}'
        results = list(cmd.run())
        
        # Verify output property works (lazy evaluation via property)
        output = cmd.output
        self.assertIsInstance(output, str, "Output property should return a string")
        
        # Verify _output_lines is used internally (list-based for efficiency)
        self.assertIsInstance(cmd._output_lines, list, "Output lines should be stored as list")
        
        # Output will contain lines from the command stdout
        # This tests that the list-based approach works correctly
        self.assertGreater(len(cmd._output_lines), 0, "Output lines should be accumulated")
        
    def test_duplicate_check_skipped_for_large_tasks(self):
        """Test that duplicate checking is skipped for large single-task outputs."""
        count = 2000  # Above the 1000 threshold
        
        start_time = time.time()
        
        cmd = MockHighVolumeCommand(
            print_line=False,
            print_item=False,
            print_stat=False,
            process=True,
            enable_duplicate_check=True  # Explicitly enable
        )
        cmd.cmd = f'seq 1 {count}'
        results = list(cmd.run())
        
        elapsed = time.time() - start_time
        
        # Should still be fast even with duplicate check enabled
        # because it gets skipped for high-volume tasks
        throughput = count / elapsed
        self.assertGreaterEqual(
            throughput,
            500,
            f"Throughput {throughput:.0f} items/sec suggests duplicate check was not skipped"
        )


if __name__ == '__main__':
    unittest.main()
