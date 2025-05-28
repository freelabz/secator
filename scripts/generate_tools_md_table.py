from secator.loader import discover_tasks

import re
from pathlib import Path


TABLE_START_MARKER = "<!-- START_TOOLS_TABLE -->"
TABLE_END_MARKER = "<!-- END_TOOLS_TABLE -->"
README_FILENAME = "README.md"


def get_tools_data():
    data = []
    hardcoded_urls = {
        'bbot': 'https://github.com/blacklanternsecurity/bbot',
        'bup': 'https://github.com/laluka/bypass-url-parser',
        'dirsearch': 'https://github.com/maurosoria/dirsearch',
        'gf': 'https://github.com/tomnomnom/gf',
        'testssl': 'https://github.com/testssl/testssl.sh',
        'wpscan': 'https://github.com/wpscanteam/wpscan',
        'nmap': 'https://github.com/nmap/nmap',
        'maigret': 'https://github.com/soxoj/maigret',
        'h8mail': 'https://github.com/khast3x/h8mail',
        'fping': 'https://github.com/schweikert/fping',
        'msfconsole': 'https://docs.rapid7.com/metasploit/msf-overview/',
        'searchsploit': 'https://gitlab.com/exploit-database/exploitdb'
    }
    for task in discover_tasks():
        url = task.install_github_handle
        if url:
            url = f'https://github.com/{url}'
        else:
            url = hardcoded_urls.get(task.__name__)
        data.append({
            'name': task.__name__,
            'url': url,
            'description': task.__doc__ or '',
            'category': '/'.join(task.tags)
        })
    return data

def generate_tools_table_markdown(tools_data):
    """
    Generates the Markdown table string from the tools data.
    Uses the formatting style found in the original README.
    """
    if not tools_data:
        return ""

    # Define fixed widths based roughly on the original table for nice formatting in raw markdown
    # Note: This is for raw readability; Markdown renderers don't strictly need it.
    # Adjust these widths if your content significantly changes length.
    name_col_width = 63 # Adjusted for link markup
    desc_col_width = 80
    cat_col_width = 17

    header = f"| {'Name'.ljust(name_col_width)} | {'Description'.ljust(desc_col_width)} | {'Category'.ljust(cat_col_width)} |"
    separator = f"|{'-' * (name_col_width + 2)}|{'-' * (desc_col_width + 2)}|{'-' * (cat_col_width + 2)}|"

    table_lines = [header, separator]

    for tool in tools_data:
        name = tool.get('name', 'N/A')
        url = tool.get('url', '#') # Default to '#' if URL is missing
        description = tool.get('description', '')
        category = tool.get('category', '')

        # Format columns
        name_md = f"[{name}]({url})"
        # Pad based on the *visible* length of the markdown link for alignment
        # This is an approximation, perfect alignment is tricky with variable link lengths
        name_padded = name_md.ljust(name_col_width + len(name_md) - len(name))

        desc_padded = description.ljust(desc_col_width)

        cat_md = f"`{category}`" if category else ''
        cat_padded = cat_md.ljust(cat_col_width)

        table_lines.append(f"| {name_padded} | {desc_padded} | {cat_padded} |")

    return "\n".join(table_lines)


def update_readme_table(readme_path, new_table_content):
    """
    Reads the README, replaces the content between the markers
    with the new table content, and writes it back.
    """
    try:
        with readme_path.open('r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: README file not found at '{readme_path}'")
        return False
    except Exception as e:
        print(f"Error reading README file: {e}")
        return False

    # Use regex to find the content between markers, including the markers themselves
    # re.DOTALL makes '.' match newlines
    pattern = re.compile(f"({re.escape(TABLE_START_MARKER)}).*?({re.escape(TABLE_END_MARKER)})", re.DOTALL)

    # Construct the replacement string, keeping the markers but replacing the middle
    replacement_string = f"{TABLE_START_MARKER}\n{new_table_content}\n{TABLE_END_MARKER}"

    # Replace the old table section with the new one
    new_content, num_replacements = pattern.subn(replacement_string, content)

    if num_replacements == 0:
        print(f"Error: Could not find table markers '{TABLE_START_MARKER}' and/or '{TABLE_END_MARKER}' in '{readme_path}'.")
        print("Please ensure the markers exist exactly as defined and surround the table.")
        return False
    elif num_replacements > 1:
        print(f"Warning: Found multiple instances of table markers in '{readme_path}'. Replacing only the first instance.")
        # pattern.sub replaces only the first instance by default if global flag isn't used,
        # but subn counts all potential matches. Behavior might be unexpected with multiple matches.
        # Consider stopping if > 1 found for safety.

    try:
        with readme_path.open('w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Successfully updated the supported tools table in '{readme_path}'")
        return True
    except Exception as e:
        print(f"Error writing updated content to README file: {e}")
        return False

data = get_tools_data()
md_table = generate_tools_table_markdown(data)
path = Path(__file__).parent.parent / 'README.md'
update_readme_table(path, md_table)
