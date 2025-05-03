secator health --bleeding 1> to_install.sh 2> output.log
chmod +x to_install.sh
./to_install.sh

echo "changes_made=false" >> $GITHUB_OUTPUT

echo "Parsing health check output..."
outdated=$(grep -E 'is outdated' output.log)
echo ""
echo "Outdated lines:"
echo "$outdated"

tool_version=$(echo "$outdated" | sed -n 's/.*\[WRN\] \([^ ]*\) is .* latest:\([^)]*\)\.*)\./\1 \2/p')
echo ""
echo "Tool versions to update:"
echo "$tool_version"

while read -r tool version; do
  echo "Processing update for '$tool' to version '$version'"
  file_path="secator/tasks/${tool}.py" # Construct file path

  if [ -f "$file_path" ]; then
    echo "Updating $file_path to version $version..."
    sed -i "s|install_version = '.*'|install_version = '${version}'|" "$file_path"
    if ! git diff --quiet "$file_path"; then
        echo "File $file_path updated successfully."
        echo "changes_made=true" >> $GITHUB_OUTPUT
    else
        echo "Warning: sed command did not modify $file_path as expected."
    fi
  else
    echo "Warning: Task file $file_path not found for tool '$tool'."
  fi
done <<< "$tool_version"
