class Config:
    def __init__(self, **kwargs):
        self.shell = kwargs.get('shell', 'fish')
        self.gif_output_path = kwargs.get('gif_output_path', 'demo.gif')
        self.font_size = kwargs.get('font_size', 22)
        self.width = kwargs.get('width', 1920)
        self.height = kwargs.get('height', 1080)
        self.border_radius = kwargs.get('border_radius', 10)
        self.line_height = kwargs.get('line_height', 1.2)
        self.wait_timeout = kwargs.get('wait_timeout', '2m')
        self.sleep_after_command = kwargs.get('sleep_after_command', '2s')
        self.sleep_after_comment = kwargs.get('sleep_after_comment', '1s')
        self.sleep_after_no_enter = kwargs.get('sleep_after_no_enter', '500ms')

def process_commands(input_lines, config):
    output_lines = [
        "# CONFIG_START",
        f"Output {config.gif_output_path}",
        f"Set Shell {config.shell}",
        f"Set FontSize {config.font_size}",
        f"Set Width {config.width}",
        f"Set Height {config.height}",
        f"Set BorderRadius {config.border_radius}",
        f"Set LineHeight {config.line_height}",
        f"Set WaitTimeout {config.wait_timeout}",
    ]
    if config.shell == 'fish': # disable fish auto-suggestions
        output_lines.extend([
            "Hide",
            "Type \"set -g fish_autosuggestion_enabled 0\"",
            "Enter",
            "Wait",
            "Type \"clear\"",
            "Enter",
            "Wait",
            "Show"
        ])
    output_lines.append("# CONFIG_END\n")

    # Define special VHS commands that should not be wrapped with "Type"
    special_commands = {"Up", "Down", "Left", "Right", "Backspace", "Ctrl+C", "Ctrl+X", "Enter", "Tab", "Space", "Hide", "Show", "Screenshot", "Copy", "Paste", "Source", "Env", "Sleep", "Wait"}

    for line in input_lines:
        line = line.strip()
        if not line:
            output_lines.append("")
            continue
        
        if line.startswith('#'):
            output_lines.append(f"Type \"{line}\"")
            output_lines.append("Enter")
            output_lines.append(f"Sleep {config.sleep_after_comment}")
            output_lines.append("")
            continue

        # Check if the line is a special command
        parts = line.split()
        command = parts[0]
        if command in special_commands:
            output_lines.append(line)
        else:
            eol_comment = line.split('#')[-1]
            hidden_commands = [c.strip() for c in eol_comment.split(',')]
            if hidden_commands:
                line = line.replace(f' #{eol_comment}', '')

            # Process hidden commands
            noenter = "noenter" in hidden_commands
            nowait = "nowait" in hidden_commands
            hide = "hide" in hidden_commands or command == "clear"

            # Process line
            if hide:
                output_lines.append("Hide")
            output_lines.append(f"Type \"{line}\"")
            if not noenter:
                output_lines.append("Sleep 500ms")
                output_lines.append("Enter")
            if not noenter and not nowait:
                output_lines.append("Wait")
            if hide:
                output_lines.append("Show")
            output_lines.append(f"Sleep {config.sleep_after_command}")
            output_lines.append("")

    return output_lines

def read_input_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def write_output_file(file_path, output_lines):
    with open(file_path, 'w') as file:
        file.writelines(line + '\n' for line in output_lines)

# Configuration settings
config = Config()

# Usage Example
input_file_path = 'test2.tap'  # This file should contain your simplified commands
output_file_path = 'test2.tape'

# Read the simplified input, process the commands, and write them to the output file
input_lines = read_input_file(input_file_path)
output_lines = process_commands(input_lines, config)
write_output_file(output_file_path, output_lines)

print(f"Processed vhs script has been written to {output_file_path}")